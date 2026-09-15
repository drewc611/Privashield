# Local Dashboard

PrivaShield includes a dependency-light local security console served by Nginx. It is packaged with the Docker Compose stack and is available only on the loopback interface by default.

## Views

- Overview: local component health, event metrics, live telemetry, audit integrity.
- Activity: normalized security events from Suricata, Zeek, and future sensors.
- AI Firewall: observe/simulate mode, threshold control, and non-enforcing policy evaluation.
- Threat Interpreter: local Ollama analysis of selected stored events.
- Sensors: collector heartbeat and freshness.
- Audit: hash-chain verification and recent control-plane actions.

## Safety

The network isolation control is deliberately disabled during Phase 1. The dashboard cannot alter nftables, eBPF programs, network interfaces, processes, sessions, credentials, or API keys.

## Local access

Default URL:

```text
http://127.0.0.1:8080
```

The dashboard proxies API and WebSocket traffic to the internal API container. The browser does not contact Ollama, PostgreSQL, or NATS directly.

## Local AI

AI remains opt-in because the model download can consume multiple gigabytes. To bootstrap the stack and pull the configured local model:

```bash
./scripts/install.sh --with-ai
```

Without that option, all non-AI dashboard functions remain available and `/api/v1/ai/status` reports AI as disabled.
