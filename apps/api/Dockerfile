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

RUN useradd --create-home --uid 10001 privashield
USER privashield

EXPOSE 8000

CMD ["uvicorn", "privashield_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
