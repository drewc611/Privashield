# WAF and Response Orchestration

## Web Application Firewall

PrivaShield's default local browser path is fronted by the official OWASP CRS Coraza+Caddy LTS container. The dashboard is no longer published directly to the host by Docker Compose.

Default settings:

- OWASP CRS 4.25 LTS image
- Coraza rule engine `On`
- CRS paranoia level 1
- blocking paranoia level 1
- JSON audit records stored in a dedicated local Docker volume
- WAF published only on `127.0.0.1` by default

Operators should tune exclusions and paranoia before placing PrivaShield in front of unrelated production applications.

## Response Orchestration

The response API models containment workflows without giving the application privileged host capabilities yet.

Workflow:

1. Create a response action.
2. The action remains `pending`.
3. An explicit operator approval moves it to `approved`.
4. The Phase 3 executor can only simulate the action.
5. The final state is `simulated` with `enforced=false`, or the action can be cancelled.

Supported planned actions include IP block, interface isolation, session termination, token revocation, file quarantine, and process stop. These are workflow types, not claims that the current release can execute them.

Every transition is written to the tamper-evident audit ledger.
