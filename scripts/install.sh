#!/usr/bin/env sh
set -eu

WITH_AI=0
if [ "${1:-}" = "--with-ai" ]; then
  WITH_AI=1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine or Docker Desktop first." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose v2 is required." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Review the local database password before shared use."
fi

if [ "$WITH_AI" -eq 1 ]; then
  if grep -q '^PRIVASHIELD_OLLAMA_ENABLED=' .env; then
    sed -i.bak 's/^PRIVASHIELD_OLLAMA_ENABLED=.*/PRIVASHIELD_OLLAMA_ENABLED=true/' .env
    rm -f .env.bak
  else
    printf '\nPRIVASHIELD_OLLAMA_ENABLED=true\n' >> .env
  fi
fi

docker compose up -d --build

if [ "$WITH_AI" -eq 1 ]; then
  MODEL=$(grep '^PRIVASHIELD_OLLAMA_MODEL=' .env | cut -d= -f2- || true)
  MODEL=${MODEL:-gemma3}
  echo "Pulling local Ollama model: $MODEL"
  docker compose exec ollama ollama pull "$MODEL"
  docker compose restart api
fi

PORT=$(grep '^PRIVASHIELD_DASHBOARD_PORT=' .env | cut -d= -f2- || true)
PORT=${PORT:-8080}
echo "PrivaShield is starting at http://127.0.0.1:$PORT"
echo "API documentation: http://127.0.0.1:8000/docs"
