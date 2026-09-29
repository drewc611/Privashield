FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml requirements.lock README.md LICENSE ./
COPY apps/api ./apps/api
# Dependencies come from the hash-locked file; the project itself is installed without resolving again.
RUN python -m pip install --upgrade pip \
    && python -m pip install --require-hashes -r requirements.lock \
    && python -m pip install --no-deps .
COPY services/collector ./services/collector

RUN useradd --create-home --uid 10003 privashield-collector
USER privashield-collector
ENV PYTHONPATH=/app/services/collector

ENTRYPOINT ["python", "-m", "privashield_collector.cli"]
