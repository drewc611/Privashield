FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY apps/api ./apps/api
RUN python -m pip install --upgrade pip && python -m pip install .
COPY services/collector ./services/collector

RUN useradd --create-home --uid 10003 privashield-collector
USER privashield-collector
ENV PYTHONPATH=/app/services/collector

ENTRYPOINT ["python", "-m", "privashield_collector.cli"]
