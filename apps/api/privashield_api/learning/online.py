"""Incremental classifiers that learn one observation at a time.

Threats do not arrive as a training set, so these models update per observation
and never need a retraining batch. Everything here is pure standard library:
shipping a tensor framework into a local-first privacy appliance would add
hundreds of megabytes and a large dependency surface to run a model whose
parameter count fits comfortably in a Python list.

Determinism is a requirement, not a preference. The repository gates merges on a
detection benchmark with committed thresholds, so a trainer whose output depends
on unseeded randomness or dictionary iteration order would make that gate
meaningless. Initialization is seeded, iteration is sorted, and the same
sequence of updates always produces the same weights.

Both models clip the per-sample gradient. That is a security control as much as
a numerical one: it bounds how far any single piece of feedback can move the
decision boundary, which is what makes a slow poisoning campaign expensive
rather than cheap.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable

from .features import hash_to_dense

# Beyond this magnitude the logistic curve is flat to within float precision.
# Clamping avoids math.exp overflow on extreme scores without changing results.
_SIGMOID_LIMIT = 60.0


def sigmoid(value: float) -> float:
    """Numerically stable logistic function."""
    if value >= _SIGMOID_LIMIT:
        return 1.0
    if value <= -_SIGMOID_LIMIT:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


def _clip(value: float, limit: float) -> float:
    return max(-limit, min(limit, value))


@runtime_checkable
class OnlineClassifier(Protocol):
    """A classifier that can be scored and updated one sample at a time."""

    #: Stable identifier recorded alongside every score, so an assessment can
    #: always be traced back to the kind of model that produced it.
    kind: str

    def predict(self, features: Mapping[str, float]) -> float:
        """Return a calibrated probability in [0, 1]."""
        ...

    def update(self, features: Mapping[str, float], label: float, weight: float) -> float:
        """Apply one weighted update. Returns the loss before the update."""
        ...

    def to_state(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        ...


class OnlineLogisticRegression:
    """Sparse online logistic regression with AdaGrad and L2 regularization.

    This is the default for a reason. On tabular security telemetry with the
    number of labels an analyst team realistically produces, a linear model is
    typically at least as accurate as a small network and has two properties the
    network does not: its weights are directly readable, so "why did this score
    go up" has an answer, and it cannot silently memorize a rare combination of
    features that amounts to a single host's identity.

    AdaGrad gives per-feature learning rates, which matters when features arrive
    at wildly different frequencies — `severity_high` appears constantly while a
    given hashed process bucket may appear twice a week.
    """

    kind = "online_logistic_regression"

    def __init__(
        self,
        *,
        learning_rate: float = 0.1,
        l2: float = 1.0e-6,
        gradient_clip: float = 1.0,
    ) -> None:
        if learning_rate <= 0.0:
            raise ValueError("learning_rate must be positive")
        if l2 < 0.0:
            raise ValueError("l2 must be non-negative")
        if gradient_clip <= 0.0:
            raise ValueError("gradient_clip must be positive")
        self.learning_rate = learning_rate
        self.l2 = l2
        self.gradient_clip = gradient_clip
        self._weights: dict[str, float] = {}
        self._squared_gradients: dict[str, float] = {}
        self.updates = 0

    def predict(self, features: Mapping[str, float]) -> float:
        total = 0.0
        for name, value in features.items():
            total += self._weights.get(name, 0.0) * value
        return sigmoid(total)

    def update(self, features: Mapping[str, float], label: float, weight: float = 1.0) -> float:
        if not 0.0 <= label <= 1.0:
            raise ValueError("label must be in [0, 1]")
        if weight < 0.0:
            raise ValueError("weight must be non-negative")
        if weight == 0.0:
            return 0.0

        prediction = self.predict(features)
        loss = _log_loss(prediction, label)
        error = prediction - label

        # Sorted iteration keeps floating-point accumulation reproducible.
        for name in sorted(features):
            value = features[name]
            gradient = _clip(error * value * weight, self.gradient_clip)
            gradient += self.l2 * self._weights.get(name, 0.0)
            accumulated = self._squared_gradients.get(name, 0.0) + gradient * gradient
            self._squared_gradients[name] = accumulated
            step = self.learning_rate * gradient / math.sqrt(accumulated + 1.0e-8)
            self._weights[name] = self._weights.get(name, 0.0) - step

        self.updates += 1
        return loss

    def top_features(self, limit: int = 10) -> list[tuple[str, float]]:
        """Return the features currently pushing hardest in either direction.

        This is what makes a learned score explainable to an analyst, and what
        lets a reviewer notice that the model has latched onto something it
        should not have.
        """
        ranked = sorted(self._weights.items(), key=lambda item: (-abs(item[1]), item[0]))
        return ranked[:limit]

    def explain(self, features: Mapping[str, float], limit: int = 5) -> list[tuple[str, float]]:
        """Per-feature contributions to this specific prediction."""
        contributions = [
            (name, self._weights.get(name, 0.0) * value) for name, value in features.items()
        ]
        contributions.sort(key=lambda item: (-abs(item[1]), item[0]))
        return [item for item in contributions[:limit] if item[1] != 0.0]

    def to_state(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "learning_rate": self.learning_rate,
            "l2": self.l2,
            "gradient_clip": self.gradient_clip,
            "updates": self.updates,
            "weights": dict(sorted(self._weights.items())),
            "squared_gradients": dict(sorted(self._squared_gradients.items())),
        }

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> OnlineLogisticRegression:
        if state.get("kind") != cls.kind:
            raise ValueError(f"state is not {cls.kind!r}: {state.get('kind')!r}")
        model = cls(
            learning_rate=float(state["learning_rate"]),
            l2=float(state["l2"]),
            gradient_clip=float(state["gradient_clip"]),
        )
        model._weights = {str(k): float(v) for k, v in state["weights"].items()}
        model._squared_gradients = {str(k): float(v) for k, v in state["squared_gradients"].items()}
        model.updates = int(state["updates"])
        return model


class OnlineMLP:
    """A one-hidden-layer neural network trained by online backpropagation.

    Included because some relationships in this data genuinely are not linear —
    an ephemeral source port is unremarkable on its own and unremarkable on an
    inbound connection, but the combination is worth a second look, and a linear
    model cannot represent that interaction without being told to.

    It is not the default. With the label volume a real analyst team produces
    this will overfit before it generalizes, and its weights answer no question
    an analyst would want to ask. Switch to it when you have the labels to
    justify it and the canary evaluation to prove it helped.

    Inputs arrive through signed feature hashing, so the input width is fixed no
    matter how many distinct values the sensors observe.

    On learning rate: because updates are applied one sample at a time with no
    batch to average over, rates above roughly 0.2 oscillate instead of
    converging. Measured on XOR, which this model must be able to separate:
    0.05 and 0.1 converge for every seed and hidden width tried, 0.3 and 0.5
    never settle. The default stays well inside the stable range.
    """

    kind = "online_mlp"

    def __init__(
        self,
        *,
        input_dimension: int = 256,
        hidden_units: int = 16,
        learning_rate: float = 0.05,
        gradient_clip: float = 1.0,
        seed: int = 20260923,
    ) -> None:
        if input_dimension <= 0:
            raise ValueError("input_dimension must be positive")
        if hidden_units <= 0:
            raise ValueError("hidden_units must be positive")
        if learning_rate <= 0.0:
            raise ValueError("learning_rate must be positive")
        if gradient_clip <= 0.0:
            raise ValueError("gradient_clip must be positive")

        self.input_dimension = input_dimension
        self.hidden_units = hidden_units
        self.learning_rate = learning_rate
        self.gradient_clip = gradient_clip
        self.seed = seed
        self.updates = 0

        # Seeded Xavier-style initialization. A dedicated Random instance rather
        # than the module-level one, so constructing a model never perturbs
        # global random state that something else may depend on.
        rng = random.Random(seed)
        limit = math.sqrt(6.0 / (input_dimension + hidden_units))
        self.hidden_weights: list[list[float]] = [
            [rng.uniform(-limit, limit) for _ in range(input_dimension)]
            for _ in range(hidden_units)
        ]
        self.hidden_bias: list[float] = [0.0] * hidden_units
        output_limit = math.sqrt(6.0 / (hidden_units + 1))
        self.output_weights: list[float] = [
            rng.uniform(-output_limit, output_limit) for _ in range(hidden_units)
        ]
        self.output_bias = 0.0

    def _forward(self, dense: Sequence[float]) -> tuple[list[float], float]:
        hidden: list[float] = []
        for unit in range(self.hidden_units):
            row = self.hidden_weights[unit]
            total = self.hidden_bias[unit]
            for index, value in enumerate(dense):
                if value != 0.0:
                    total += row[index] * value
            hidden.append(math.tanh(total))
        output = self.output_bias
        for unit in range(self.hidden_units):
            output += self.output_weights[unit] * hidden[unit]
        return hidden, sigmoid(output)

    def predict(self, features: Mapping[str, float]) -> float:
        dense = hash_to_dense(features, self.input_dimension)
        _, probability = self._forward(dense)
        return probability

    def update(self, features: Mapping[str, float], label: float, weight: float = 1.0) -> float:
        if not 0.0 <= label <= 1.0:
            raise ValueError("label must be in [0, 1]")
        if weight < 0.0:
            raise ValueError("weight must be non-negative")
        if weight == 0.0:
            return 0.0

        dense = hash_to_dense(features, self.input_dimension)
        hidden, prediction = self._forward(dense)
        loss = _log_loss(prediction, label)

        # Backpropagation. The derivative of log loss through a sigmoid output
        # collapses to (prediction - label), which is why no separate sigmoid
        # derivative term appears here.
        output_delta = _clip((prediction - label) * weight, self.gradient_clip)

        hidden_deltas: list[float] = []
        for unit in range(self.hidden_units):
            derivative = 1.0 - hidden[unit] * hidden[unit]  # d/dx tanh(x)
            hidden_deltas.append(
                _clip(output_delta * self.output_weights[unit] * derivative, self.gradient_clip)
            )

        for unit in range(self.hidden_units):
            self.output_weights[unit] -= self.learning_rate * output_delta * hidden[unit]
        self.output_bias -= self.learning_rate * output_delta

        for unit in range(self.hidden_units):
            delta = hidden_deltas[unit]
            if delta == 0.0:
                continue
            row = self.hidden_weights[unit]
            step = self.learning_rate * delta
            for index, value in enumerate(dense):
                if value != 0.0:
                    row[index] -= step * value
            self.hidden_bias[unit] -= step

        self.updates += 1
        return loss

    def to_state(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "input_dimension": self.input_dimension,
            "hidden_units": self.hidden_units,
            "learning_rate": self.learning_rate,
            "gradient_clip": self.gradient_clip,
            "seed": self.seed,
            "updates": self.updates,
            "hidden_weights": [list(row) for row in self.hidden_weights],
            "hidden_bias": list(self.hidden_bias),
            "output_weights": list(self.output_weights),
            "output_bias": self.output_bias,
        }

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> OnlineMLP:
        if state.get("kind") != cls.kind:
            raise ValueError(f"state is not {cls.kind!r}: {state.get('kind')!r}")
        model = cls(
            input_dimension=int(state["input_dimension"]),
            hidden_units=int(state["hidden_units"]),
            learning_rate=float(state["learning_rate"]),
            gradient_clip=float(state["gradient_clip"]),
            seed=int(state["seed"]),
        )
        model.hidden_weights = [[float(v) for v in row] for row in state["hidden_weights"]]
        model.hidden_bias = [float(v) for v in state["hidden_bias"]]
        model.output_weights = [float(v) for v in state["output_weights"]]
        model.output_bias = float(state["output_bias"])
        model.updates = int(state["updates"])
        return model


def _log_loss(prediction: float, label: float) -> float:
    """Binary cross-entropy, clamped away from log(0)."""
    epsilon = 1.0e-12
    clamped = min(max(prediction, epsilon), 1.0 - epsilon)
    return -(label * math.log(clamped) + (1.0 - label) * math.log(1.0 - clamped))


def model_from_state(state: Mapping[str, Any]) -> OnlineLogisticRegression | OnlineMLP:
    """Rebuild whichever model kind a persisted state describes."""
    kind = state.get("kind")
    if kind == OnlineLogisticRegression.kind:
        return OnlineLogisticRegression.from_state(state)
    if kind == OnlineMLP.kind:
        return OnlineMLP.from_state(state)
    raise ValueError(f"unknown model kind: {kind!r}")


__all__ = [
    "OnlineClassifier",
    "OnlineLogisticRegression",
    "OnlineMLP",
    "model_from_state",
    "sigmoid",
]
