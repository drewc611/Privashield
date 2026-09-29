from __future__ import annotations

import math

import pytest

from privashield_api.learning.online import (
    OnlineClassifier,
    OnlineLogisticRegression,
    OnlineMLP,
    model_from_state,
    sigmoid,
)

MALICIOUS = {"bias": 1.0, "severity_ordinal": 1.0, "dst_port_rdp": 1.0}
BENIGN = {"bias": 1.0, "severity_ordinal": 0.0, "dst_port_wellknown": 1.0}


def models() -> list[OnlineLogisticRegression | OnlineMLP]:
    return [OnlineLogisticRegression(), OnlineMLP(input_dimension=64, hidden_units=8)]


# --------------------------------------------------------------------------
# sigmoid
# --------------------------------------------------------------------------


def test_sigmoid_is_centred_and_bounded() -> None:
    assert sigmoid(0.0) == 0.5
    assert 0.0 <= sigmoid(-1000.0) <= 1.0
    assert 0.0 <= sigmoid(1000.0) <= 1.0


def test_sigmoid_does_not_overflow_on_extreme_input() -> None:
    # math.exp(1000) raises OverflowError; the clamp is what prevents it.
    assert sigmoid(1e6) == 1.0
    assert sigmoid(-1e6) == 0.0


# --------------------------------------------------------------------------
# Both models: the learning contract
# --------------------------------------------------------------------------


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_untrained_model_expresses_no_strong_opinion(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    # A fresh model must not look confident. Scores near 0.5 are what let the
    # engine report low confidence rather than a fabricated judgement.
    assert 0.2 < model.predict(MALICIOUS) < 0.8


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_model_separates_classes_after_training(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    # AdaGrad's accumulating denominator means convergence is steady rather
    # than fast: with only three features this reaches 0.87/0.21 by 60 updates
    # and 0.92/0.14 by 120. Measured, not guessed.
    for _ in range(120):
        model.update(MALICIOUS, 1.0, 1.0)
        model.update(BENIGN, 0.0, 1.0)
    assert model.predict(MALICIOUS) > 0.8
    assert model.predict(BENIGN) < 0.2


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_loss_decreases_as_the_model_learns(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    first = model.update(MALICIOUS, 1.0, 1.0)
    for _ in range(40):
        model.update(MALICIOUS, 1.0, 1.0)
    last = model.update(MALICIOUS, 1.0, 1.0)
    assert last < first


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_update_counter_tracks_applied_updates(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    assert model.updates == 0
    model.update(MALICIOUS, 1.0, 1.0)
    model.update(BENIGN, 0.0, 1.0)
    assert model.updates == 2


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_zero_weight_update_is_a_no_op(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    # The guard expresses "refused" as zero weight, so this has to change nothing.
    before = model.predict(MALICIOUS)
    assert model.update(MALICIOUS, 1.0, 0.0) == 0.0
    assert model.predict(MALICIOUS) == before
    assert model.updates == 0


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_weight_scales_influence(model: OnlineLogisticRegression | OnlineMLP) -> None:
    heavy = (
        type(model)()
        if isinstance(model, OnlineLogisticRegression)
        else OnlineMLP(input_dimension=64, hidden_units=8)
    )
    light = (
        type(model)()
        if isinstance(model, OnlineLogisticRegression)
        else OnlineMLP(input_dimension=64, hidden_units=8)
    )
    heavy.update(MALICIOUS, 1.0, 1.0)
    light.update(MALICIOUS, 1.0, 0.1)
    assert heavy.predict(MALICIOUS) > light.predict(MALICIOUS)


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_rejects_out_of_range_labels(model: OnlineLogisticRegression | OnlineMLP) -> None:
    with pytest.raises(ValueError, match="label"):
        model.update(MALICIOUS, 1.5, 1.0)
    with pytest.raises(ValueError, match="label"):
        model.update(MALICIOUS, -0.1, 1.0)


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_rejects_negative_weight(model: OnlineLogisticRegression | OnlineMLP) -> None:
    with pytest.raises(ValueError, match="weight"):
        model.update(MALICIOUS, 1.0, -1.0)


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_predictions_stay_in_probability_range(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    for _ in range(200):
        model.update(MALICIOUS, 1.0, 1.0)
    assert 0.0 <= model.predict(MALICIOUS) <= 1.0
    assert 0.0 <= model.predict(BENIGN) <= 1.0


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_satisfies_the_classifier_protocol(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    assert isinstance(model, OnlineClassifier)


# --------------------------------------------------------------------------
# Determinism — the benchmark gate depends on it
# --------------------------------------------------------------------------


def test_logistic_training_is_reproducible() -> None:
    def train() -> dict[str, float]:
        model = OnlineLogisticRegression()
        for index in range(50):
            model.update(MALICIOUS if index % 2 else BENIGN, float(index % 2), 1.0)
        return dict(model.to_state()["weights"])

    assert train() == train()


def test_mlp_initialization_is_seeded() -> None:
    first = OnlineMLP(seed=42)
    second = OnlineMLP(seed=42)
    third = OnlineMLP(seed=43)
    assert first.hidden_weights == second.hidden_weights
    assert first.hidden_weights != third.hidden_weights


def test_mlp_training_is_reproducible() -> None:
    def train() -> list[float]:
        model = OnlineMLP(input_dimension=32, hidden_units=4, seed=7)
        for index in range(30):
            model.update(MALICIOUS if index % 2 else BENIGN, float(index % 2), 1.0)
        return list(model.output_weights)

    assert train() == train()


def test_constructing_a_model_does_not_disturb_global_random_state() -> None:
    import random

    random.seed(1234)
    expected = [random.random() for _ in range(3)]
    random.seed(1234)
    OnlineMLP(seed=999)
    assert [random.random() for _ in range(3)] == expected


# --------------------------------------------------------------------------
# Gradient clipping — bounds what one sample can do
# --------------------------------------------------------------------------


def test_gradient_clipping_bounds_a_single_update() -> None:
    clipped = OnlineLogisticRegression(gradient_clip=0.01, learning_rate=1.0)
    loose = OnlineLogisticRegression(gradient_clip=100.0, learning_rate=1.0)
    extreme = {"bias": 1.0, "spike": 1000.0}
    clipped.update(extreme, 1.0, 1.0)
    loose.update(extreme, 1.0, 1.0)
    clipped_weight = abs(dict(clipped.to_state()["weights"])["spike"])
    loose_weight = abs(dict(loose.to_state()["weights"])["spike"])
    assert clipped_weight < loose_weight


def test_one_sample_cannot_flip_a_well_trained_model() -> None:
    # The security property behind clipping: a single poisoned label must not
    # undo a model the team has spent real feedback building.
    model = OnlineLogisticRegression()
    for _ in range(200):
        model.update(MALICIOUS, 1.0, 1.0)
    confident = model.predict(MALICIOUS)
    model.update(MALICIOUS, 0.0, 1.0)  # one hostile "this is benign"
    assert model.predict(MALICIOUS) > confident - 0.2


# --------------------------------------------------------------------------
# Explainability — only the linear model can offer it
# --------------------------------------------------------------------------


def test_logistic_reports_top_weighted_features() -> None:
    model = OnlineLogisticRegression()
    for _ in range(30):
        model.update(MALICIOUS, 1.0, 1.0)
        model.update(BENIGN, 0.0, 1.0)
    names = [name for name, _ in model.top_features(5)]
    assert "dst_port_rdp" in names


def test_logistic_explains_an_individual_prediction() -> None:
    model = OnlineLogisticRegression()
    for _ in range(30):
        model.update(MALICIOUS, 1.0, 1.0)
        model.update(BENIGN, 0.0, 1.0)
    contributions = model.explain(MALICIOUS)
    assert contributions
    assert all(isinstance(name, str) for name, _ in contributions)
    # Sorted by absolute contribution, strongest first.
    magnitudes = [abs(value) for _, value in contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_explain_omits_features_with_no_influence() -> None:
    model = OnlineLogisticRegression()
    contributions = model.explain({"never_seen": 1.0})
    assert contributions == []


# --------------------------------------------------------------------------
# Validation of constructor arguments
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"learning_rate": 0.0}, "learning_rate"),
        ({"learning_rate": -1.0}, "learning_rate"),
        ({"l2": -1.0}, "l2"),
        ({"gradient_clip": 0.0}, "gradient_clip"),
    ],
)
def test_logistic_rejects_invalid_configuration(kwargs: dict[str, float], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        OnlineLogisticRegression(**kwargs)


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"input_dimension": 0}, "input_dimension"),
        ({"hidden_units": 0}, "hidden_units"),
        ({"learning_rate": 0.0}, "learning_rate"),
        ({"gradient_clip": -1.0}, "gradient_clip"),
    ],
)
def test_mlp_rejects_invalid_configuration(kwargs: dict[str, float], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        OnlineMLP(**kwargs)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Persistence round-trips
# --------------------------------------------------------------------------


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_state_round_trip_preserves_predictions(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    for _ in range(25):
        model.update(MALICIOUS, 1.0, 1.0)
        model.update(BENIGN, 0.0, 1.0)
    restored = model_from_state(model.to_state())
    assert restored.predict(MALICIOUS) == model.predict(MALICIOUS)
    assert restored.predict(BENIGN) == model.predict(BENIGN)
    assert restored.updates == model.updates


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_state_is_json_serializable(model: OnlineLogisticRegression | OnlineMLP) -> None:
    import json

    model.update(MALICIOUS, 1.0, 1.0)
    encoded = json.dumps(model.to_state())
    rebuilt = model_from_state(json.loads(encoded))
    assert rebuilt.predict(MALICIOUS) == model.predict(MALICIOUS)


@pytest.mark.parametrize("model", models(), ids=lambda m: m.kind)
def test_restored_model_continues_learning(
    model: OnlineLogisticRegression | OnlineMLP,
) -> None:
    for _ in range(20):
        model.update(MALICIOUS, 1.0, 1.0)
    restored = model_from_state(model.to_state())
    before = restored.predict(MALICIOUS)
    for _ in range(20):
        restored.update(MALICIOUS, 1.0, 1.0)
    assert restored.predict(MALICIOUS) > before


def test_model_from_state_rejects_an_unknown_kind() -> None:
    with pytest.raises(ValueError, match="unknown model kind"):
        model_from_state({"kind": "transformer_xl"})


def test_from_state_rejects_a_mismatched_kind() -> None:
    mlp_state = OnlineMLP().to_state()
    with pytest.raises(ValueError, match="online_logistic_regression"):
        OnlineLogisticRegression.from_state(mlp_state)


def test_logistic_state_is_sorted_for_reviewable_diffs() -> None:
    model = OnlineLogisticRegression()
    for name in ("zulu", "alpha", "mike"):
        model.update({name: 1.0}, 1.0, 1.0)
    weights = list(model.to_state()["weights"])
    assert weights == sorted(weights)


# --------------------------------------------------------------------------
# The network has to earn its keep: non-linear separation
# --------------------------------------------------------------------------


def test_mlp_learns_a_relationship_a_linear_model_cannot() -> None:
    # XOR over two features. A linear model provably cannot separate this; if
    # the network cannot either, backpropagation is wired up wrong.
    patterns = [
        ({"bias": 1.0, "a": 0.0, "b": 0.0}, 0.0),
        ({"bias": 1.0, "a": 1.0, "b": 0.0}, 1.0),
        ({"bias": 1.0, "a": 0.0, "b": 1.0}, 1.0),
        ({"bias": 1.0, "a": 1.0, "b": 1.0}, 0.0),
    ]
    # Learning rate matters here: above roughly 0.2 the online updates
    # oscillate and never settle. At 0.1 this converges to ~0.999/0.001 for
    # every seed and hidden width tried.
    network = OnlineMLP(input_dimension=16, hidden_units=12, learning_rate=0.1, seed=11)
    for _ in range(4000):
        for features, label in patterns:
            network.update(features, label, 1.0)

    for features, label in patterns:
        prediction = network.predict(features)
        assert (prediction > 0.5) == (label > 0.5), (
            f"XOR pattern {features} predicted {prediction:.3f}, expected {label}"
        )


def test_mlp_hidden_layer_actually_activates() -> None:
    network = OnlineMLP(input_dimension=32, hidden_units=6, seed=3)
    dense = [1.0] * 32
    hidden, output = network._forward(dense)
    assert len(hidden) == 6
    assert all(-1.0 <= value <= 1.0 for value in hidden)  # tanh range
    assert 0.0 <= output <= 1.0
    assert not all(math.isclose(value, 0.0) for value in hidden)
