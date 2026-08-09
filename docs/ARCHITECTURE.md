# Architecture

## Scope and trust boundary

Resonance is a consent-based coordinator, not a Bluetooth controller. A receiver is a browser on a participating phone, tablet, laptop, or small computer. The operating system remains responsible for pairing and selecting the physical speaker.

The coordinator trusts an operator who holds the admin token. A receiver becomes trusted only after consuming a short-lived, one-time enrollment code. Every later media request and WebSocket session uses that receiver's random credential.

## Runtime components

```text
operator browser (/admin)
        |
        | bearer-authenticated HTTP
        v
FastAPI coordinator ---- SQLite metadata/audit log
        |
        | authenticated WebSocket + authenticated media download
        v
receiver browser ---- Web Audio clock ---- selected OS audio output
```

- `resonance/main.py` owns HTTP/WebSocket contracts and orchestration.
- `resonance/realtime.py` owns the in-memory receiver connection registry and bounded concurrent fanout.
- `resonance/db.py` owns schema initialization, migrations, transactions, delivery authorization, and audit persistence.
- `resonance/security.py` owns credential generation and verification.
- `static/receiver.js` verifies, decodes, schedules, stops, and reports browser playback.
- `static/admin.js` provides the operator workflow and delivery-status dashboard.

## Critical-path invariants

1. An alert and its intended receiver delivery rows are committed in one SQLite transaction before any prepare event is sent.
2. A receiver receipt is accepted only for a delivery authorized to that receiver identity.
3. Fanout starts all socket sends concurrently; a slow peer is removed after a bounded timeout and does not delay healthy peers.
4. Blocking SQLite and credential operations run outside the asyncio event loop.
5. Stop state is durable. A receiver reconnecting after a missed live stop receives a replayed stop before any pending prepare event.
6. A receiver records stop tombstones locally, so a stop that arrives during download or decode prevents later scheduling.
7. Receiver clocks use multiple startup samples and continue calibrating from heartbeat round trips.
8. Sensitive authentication paths use process-local token buckets keyed by the ASGI peer address. Device paths combine a generous aggregate peer ceiling with stricter per-device buckets so many receivers can safely share one NAT address. Every bucket registry has a fixed maximum size and least-recently-used eviction.

## Data model

- `devices`: receiver identity, revocation, last-seen time, a legacy PBKDF2 verifier for rollback compatibility, and a fast hash of the generated high-entropy token.
- `enrollment_codes`: PBKDF2 verifier plus an indexed digest used only to find the candidate code without scanning all live codes.
- `tracks`: server filename, media metadata, and SHA-256 digest.
- `alerts`: durable schedule and stop state.
- `alert_deliveries`: the receiver identities authorized to report a given alert.
- `alert_receipts`: latest receiver state for each alert/device pair.
- `audit_events`: operator-relevant security and delivery events.

SQLite uses WAL mode. Each operation has its own connection, while multi-statement state transitions are explicit transactions.

## Deployment constraint

The connection registry is intentionally in process. Run exactly one coordinator process/replica. Multiple Uvicorn workers or replicas would split WebSocket receivers and require a shared fanout bus plus distributed presence tracking. SQLite is also a single-node data store; horizontal scale is not supported by this release.

Rate-limit state is also process-local and resets on restart. It protects the coordinator from concentrated abuse but does not replace rate limiting at the trusted reverse proxy. Resonance never parses forwarded-address headers itself; configure Uvicorn's trusted proxy behavior so the ASGI client address is authoritative.

## Failure semantics

- `delivered` means the coordinator successfully submitted the event to a receiver socket; it is not proof of audible output.
- `ready` means the browser verified and scheduled the audio.
- `playing` is a browser-side scheduled-time signal, not a microphone-confirmed acoustic signal.
- Network loss, browser suspension, Bluetooth buffering, speaker power, and OS routing remain outside the coordinator's control.
- Replayed prepare events are sent only while their start time is still in the future. Replayed stops are retained for 24 hours for receivers that have not already reported a terminal state.
