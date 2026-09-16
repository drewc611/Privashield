# Local Authentication and RBAC

PrivaShield supports an opt-in local authentication mode for self-hosted deployments. The default remains `disabled` for loopback-only development compatibility. Any non-loopback or multi-user deployment should use `local` authentication until an external identity-provider integration is available.

## Security model

Local authentication uses high-entropy bearer tokens. Raw tokens are displayed only when a principal is created or rotated. PrivaShield persists only a SHA-256 digest and a short non-secret prefix for operator identification. Raw tokens are never returned by list APIs and must not be written to logs, source control, screenshots, issue bodies, or audit payloads.

The five local roles are:

| Role | Intended authority |
| --- | --- |
| `viewer` | Read ordinary operational state and telemetry. |
| `analyst` | Viewer access plus analysis, DLP/anomaly/malware/ransomware evaluation, incident investigation, and analyst feedback. |
| `operator` | Analyst access plus sensor ingestion, firewall simulation configuration, response-action workflows, and signed-policy lifecycle operations. |
| `administrator` | Full local control-plane authority including principal lifecycle management and audit access. |
| `auditor` | Read audit evidence, policy history, and ordinary operational state without mutation authority. |

Authorization is enforced by the API middleware. Dashboard visibility is not treated as an authorization boundary.

## Enable local authentication

Set:

```text
PRIVASHIELD_AUTH_MODE=local
PRIVASHIELD_BOOTSTRAP_ADMIN_TOKEN=<high-entropy-bootstrap-secret>
```

Restart the API. The bootstrap token authenticates as `bootstrap-administrator` and exists only to establish durable local administrator principals. It is not stored in PostgreSQL.

Recommended bootstrap sequence:

1. Enable local auth with a high-entropy bootstrap token supplied through the deployment secret mechanism.
2. Use the bootstrap token to create at least two durable `administrator` principals.
3. Store their one-time bearer tokens in the operator's approved secret store.
4. Remove `PRIVASHIELD_BOOTSTRAP_ADMIN_TOKEN` and restart the API.
5. Verify the durable administrator tokens still authenticate before considering bootstrap removal complete.

PrivaShield blocks a durable administrator from disabling its own active principal. When no bootstrap token exists, it also blocks disabling the last enabled durable administrator.

## Principal API

All principal-management routes require `administrator` authority.

- `GET /api/v1/principals`
- `POST /api/v1/principals`
- `POST /api/v1/principals/{principal_id}/rotate`
- `POST /api/v1/principals/{principal_id}/disable`
- `GET /api/v1/auth/me`
- `GET /api/v1/auth/capabilities`

Example creation request:

```json
{
  "name": "soc-operator-01",
  "role": "operator"
}
```

The creation response contains the bearer token exactly once. Rotation immediately invalidates the previous token. Disabling a principal immediately invalidates its token.

## Dashboard

The local dashboard includes a bearer-token field. The token is stored only in browser `sessionStorage`, not `localStorage`, so it is cleared when the browser session is closed. Press **Clear** to remove it immediately.

The dashboard calls `/api/v1/auth/me` and displays the authenticated principal, role, and whether the credential is verified.

## WebSocket authentication

Browser WebSocket APIs cannot set an arbitrary `Authorization` header. PrivaShield therefore uses WebSocket subprotocol negotiation:

- safe selected subprotocol: `privashield`
- bearer credential subprotocol: `privashield.bearer.<token>`

The server authenticates the bearer credential before accepting the live stream and selects only the safe `privashield` protocol in the response. The bearer token is not placed in the URL or query string. Reverse proxies and observability systems must not log `Sec-WebSocket-Protocol` values because the request header can contain the credential.

## Internal collectors

Suricata, Zeek, and the file monitor read `PRIVASHIELD_API_TOKEN` when present. When local auth is enabled, create a dedicated `operator` principal for these internal producers and provide its one-time token through the deployment secret mechanism.

Do not reuse the bootstrap administrator token for collectors.

## Verified attribution

When authentication is `local`, caller-supplied actor strings do not establish identity. Human control-plane operations derive their audit actor from the authenticated principal. This applies to response-action requests/approvals/cancellations, analyst feedback, firewall configuration changes, policy registration/approval/activation/rollback, and principal lifecycle events.

Audit actor format for durable principals is:

```text
<principal-name><<principal-uuid>>
```

Legacy loopback development mode remains explicitly unverified and is labeled accordingly.

## Current limitations

- No external OIDC/SAML integration yet.
- No password login or browser cookie session. Local credentials are bearer tokens.
- Principal role changes require creating a new appropriately scoped principal and disabling the old one.
- Local bearer-token possession is sufficient authentication. Protect operator workstations and secret storage accordingly.
- Local RBAC does not authorize privileged enforcement. `privileged_execution=false` remains unchanged.
