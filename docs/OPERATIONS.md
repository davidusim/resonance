# Operations runbook

## Deployment

1. Provision persistent storage for `/data` and keep it outside the image.
2. Supply `RESONANCE_ADMIN_TOKEN` from a secret manager. Use a unique random value of at least 24 characters.
3. Run one process and one replica. Do not add Uvicorn workers.
4. Terminate TLS at a trusted reverse proxy and preserve WebSocket upgrades.
5. Restrict `/admin` through a private network, VPN, or proxy access policy.
6. Confirm `GET /healthz` returns HTTP 200 with `{"status":"ok","database":"ok"}`.
7. Apply distributed rate limits at the reverse proxy and configure Uvicorn to trust forwarded client addresses only from known proxy IPs.

The container runs as a non-root user and includes a health check. A writable persistent `/data` volume is required.

### Abuse-resistance settings

Resonance applies process-local token buckets to sensitive authentication paths. Every setting must be a positive integer; invalid configuration prevents startup.

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `RESONANCE_RATE_LIMIT_WINDOW_SECONDS` | `60` | Refill window shared by all buckets |
| `RESONANCE_RATE_LIMIT_MAX_CLIENTS` | `10000` | Maximum retained peer keys per limiter |
| `RESONANCE_ENROLLMENT_ATTEMPT_LIMIT` | `6` | Enrollment submissions per peer per window |
| `RESONANCE_DEVICE_AUTH_ATTEMPT_LIMIT` | `60` | Device HTTP and WebSocket attempts per peer/device pair per window, independently |
| `RESONANCE_DEVICE_PEER_ATTEMPT_LIMIT` | `600` | Aggregate device HTTP and WebSocket attempts per peer per window, independently |
| `RESONANCE_ADMIN_AUTH_FAILURE_LIMIT` | `10` | Invalid administrator credentials per peer per window |

HTTP limits return `429 Too Many Requests` with `Retry-After`. Limited receiver sockets close with code `4429`. A correct administrator token remains usable after invalid attempts from the same peer, avoiding an application-level lockout of emergency controls.

## Observability

HTTP responses include `X-Request-ID` and `Server-Timing`. A valid incoming request ID is preserved so proxy and application logs can be correlated. Application logs record request outcome and duration plus alert start, stop, replay, and rejected-receipt events. Routine request/event logs exclude tokens, enrollment codes, and uploaded media. If no admin token is configured, startup prints the generated token once and stores it in `/data/admin.token`; protect startup logs accordingly.

Monitor at minimum:

- health-check failures;
- HTTP 5xx and latency changes;
- repeated rejected receipts or authentication failures at the proxy;
- `rate_limit_exceeded` application log events and HTTP 429 changes;
- connected receiver count before a drill or incident;
- per-alert `ready` and `error` counts in the coordinator.

## Backup and restore

Use SQLite's online backup operation rather than copying only the main database file while WAL mode is active. With the `sqlite3` CLI installed:

```sh
sqlite3 /data/resonance.sqlite3 ".backup '/backup/resonance-$(date +%Y%m%d-%H%M%S).sqlite3'"
```

Back up the `tracks/` directory in the same recovery set. Test restores on a separate host. To restore, stop the coordinator, replace the database and tracks from one consistent recovery set, verify ownership and permissions, then start and check `/healthz`.

## Upgrade and rollback

1. Take a database-and-tracks backup.
2. Deploy the new image to a drill environment and exercise enrollment, upload, prepare, stop, reconnect, and revocation.
3. Deploy the single production replica and repeat a receiver drill.

The v0.3 schema migration is additive. Legacy PBKDF2 receiver verifiers are retained even after the faster token hash is populated, so a v0.2 code rollback can still authenticate existing and newly enrolled v0.3 devices. A data rollback still requires the pre-upgrade recovery set.

## Incident actions

- Suspected admin-token exposure: replace the secret, restart the coordinator, and review proxy/application logs.
- Receiver loss or compromise: revoke it in `/admin`; the active socket is closed and later media/socket authentication fails.
- Suspected database exposure: rotate the admin token and re-enroll receivers because their browser-held bearer tokens should be treated as potentially exposed.
- Failed alert delivery: use the independent certified notification path, preserve logs and the database, and inspect receiver power, browser state, network path, OS route, and speaker state.

## Drill checklist

- Every receiver shows Connected.
- Audio is enabled after any browser/device restart.
- The intended Bluetooth or wired output is selected and audible.
- A test alert reaches `ready`, `playing`, and `completed` on each receiver.
- A receiver disconnected during an alert stops after reconnecting.
- Revocation immediately disconnects a test receiver.
- The separate certified emergency-notification path is working.
