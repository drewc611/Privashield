# Host File Monitor

The optional host file monitor converts filesystem activity into local PrivaShield ransomware and file-risk telemetry.

## Enable

Set a directory in `.env`:

```text
PRIVASHIELD_MONITOR_PATH=/absolute/path/to/monitor
```

Then start the profile:

```bash
docker compose --profile host-monitor up -d --build
```

The directory is mounted read-only into the monitor container. PrivaShield observes changes made by the host or other processes but cannot modify monitored files through this service.

## Signals

The monitor records aggregate behavior such as:

- operation rate
- likely rename bursts
- likely extension-change bursts
- number of affected directories
- entropy of a bounded sample of newly written or modified files
- file-risk characteristics such as misleading executable extensions

Paths are hashed before they are added to security-event metadata. The file-risk audit route also hashes filenames rather than placing raw names in the audit chain.

## Limitations

Rename and extension-change counts are inferred from batches of add/delete notifications and are not guaranteed to map one-to-one to operating-system rename syscalls. Entropy is a heuristic. These signals should be combined with endpoint telemetry and signatures before containment decisions are made.
