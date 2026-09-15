.PHONY: install test lint run up down

install:
	python -m pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

run:
	uvicorn privashield_api.main:app --app-dir apps/api --reload --host 127.0.0.1 --port 8000

up:
	docker compose up --build

down:
	docker compose down
