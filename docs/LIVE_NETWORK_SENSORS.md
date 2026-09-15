# Live Network Sensors

PrivaShield can run Zeek and Suricata as optional passive Linux network sensors. The default installation does not start them because packet capture requires elevated Linux capabilities and host-network access.

## Supported sensor profile

Set the capture interface in `.env`:

```text
PRIVASHIELD_NETWORK_INTERFACE=eth0
```

Then start:

```bash
docker compose --profile network-sensors up -d --build
```

The profile starts:

- Zeek LTS using the official `zeek/zeek:lts` image
- Suricata 8.0 using the established `jasonish/suricata:8.0` image
- one PrivaShield collector for Suricata EVE JSON
- one PrivaShield collector for Zeek JSON connection logs

The collector containers do not receive packet-capture capabilities. They read sensor log volumes and forward normalized events through the existing API.

## Privilege boundary

Only the sensor containers use host networking and packet-capture capabilities. The API, dashboard, WAF, database, event bus, AI runtime, file monitor, and collectors remain in ordinary container networking.

This profile is Linux-oriented. Docker Desktop networking and interface naming differ on macOS and Windows, so native host capture should be configured separately there.

## Data minimization

PrivaShield normalizers omit DNS names, HTTP hosts, and TLS SNI unless the collector is explicitly started with `--include-application-metadata`. The packaged collectors keep that option off by default.

## IDS versus IPS

The packaged Suricata sensor runs in passive capture mode. It is not configured for NFQUEUE, AF_PACKET IPS bridging, or packet dropping. Inline enforcement remains a separate data-plane concern.
