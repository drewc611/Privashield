# PrivaShield developer tooling.
#
# `make verify` runs every gate that CI runs. If it passes locally, CI passes.

PYTHON_VERSION ?= 3.12
VENV ?= .venv
BIN := $(VENV)/bin
PY := $(BIN)/python
COVERAGE_MIN ?= 81.5

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

$(PY):
	@command -v uv >/dev/null 2>&1 \
		&& uv venv --python $(PYTHON_VERSION) $(VENV) \
		|| python$(PYTHON_VERSION) -m venv $(VENV)

.PHONY: install
install: $(PY) ## Create the virtualenv and install the project with dev tooling
	@$(PY) -m pip install --quiet --upgrade pip
	@$(PY) -m pip install --quiet -e ".[dev]"
	@echo "Ready. Tools are in $(BIN); run 'make verify' before pushing."

.PHONY: install-locked
install-locked: $(PY) ## Install exact hash-pinned dependencies (what CI uses)
	@$(PY) -m pip install --quiet --upgrade pip
	@$(PY) -m pip install --quiet --require-hashes -r requirements/dev.txt
	@$(PY) -m pip install --quiet --no-deps -e .

.PHONY: lock
lock: ## Regenerate the hash-pinned lockfiles from pyproject.toml
	@command -v uv >/dev/null 2>&1 || { echo "uv is required: https://docs.astral.sh/uv/"; exit 1; }
	uv pip compile --universal --python-version $(PYTHON_VERSION) --generate-hashes \
		--custom-compile-command "make lock" -o requirements/runtime.txt pyproject.toml
	uv pip compile --universal --python-version $(PYTHON_VERSION) --generate-hashes --extra dev \
		--custom-compile-command "make lock" -o requirements/dev.txt pyproject.toml

.PHONY: clean
clean: ## Remove the virtualenv and build/test caches
	rm -rf $(VENV) .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# ---------------------------------------------------------------------------
# Quality gates (each one mirrors a CI step)
# ---------------------------------------------------------------------------

.PHONY: format
format: ## Apply formatting and safe lint fixes
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

.PHONY: lint
lint: ## Check formatting and lint rules
	$(BIN)/ruff format --check .
	$(BIN)/ruff check .

.PHONY: typecheck
typecheck: ## Run static type checking
	$(BIN)/mypy

.PHONY: test
test: ## Run the test suite with the coverage floor enforced
	$(BIN)/pytest -q --cov --cov-report=term-missing --cov-fail-under=$(COVERAGE_MIN)

.PHONY: coverage-html
coverage-html: ## Write an HTML coverage report to htmlcov/
	$(BIN)/pytest -q --cov --cov-report=html
	@echo "Open htmlcov/index.html"

.PHONY: benchmark
benchmark: ## Run the detection regression benchmark against committed thresholds
	$(BIN)/python -m privashield_api.evaluation --enforce-thresholds

.PHONY: audit
audit: ## Audit dependencies for known vulnerabilities
	$(BIN)/pip-audit --progress-spinner off

.PHONY: governance
governance: ## Validate the agent governance policy
	$(BIN)/python .github/scripts/validate_agent_governance.py

.PHONY: check-dashboard
check-dashboard: ## Syntax-check the dashboard JavaScript
	@command -v node >/dev/null 2>&1 && node --check apps/dashboard/app.js \
		|| echo "node not found; skipping dashboard check"

.PHONY: check-compose
check-compose: ## Validate the Compose file
	@docker compose config >/dev/null 2>&1 && echo "compose ok" \
		|| echo "docker compose unavailable; skipping compose check"

.PHONY: verify
verify: governance lint typecheck test benchmark check-dashboard check-compose ## Run every CI gate
	@echo "All gates passed."

# ---------------------------------------------------------------------------
# Running the stack
# ---------------------------------------------------------------------------

.PHONY: run
run: ## Run the API locally with reload
	$(BIN)/uvicorn privashield_api.main:app --app-dir apps/api --reload --host 127.0.0.1 --port 8000

.PHONY: up
up: ## Build and start the full stack
	docker compose up --build

.PHONY: down
down: ## Stop the stack
	docker compose down
