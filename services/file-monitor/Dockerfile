FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY apps/api ./apps/api
RUN python -m pip install --upgrade pip && python -m pip install .
COPY services/file-monitor ./services/file-monitor

RUN useradd --create-home --uid 10002 privashield-monitor
USER privashield-monitor
ENV PYTHONPATH=/app/services/file-monitor

CMD ["python", "-m", "privashield_file_monitor.monitor"]
