# Changelog

## 0.4.0

- Added application-level rate limits for enrollment, device HTTP authentication, receiver WebSocket authentication, and invalid administrator credentials.
- Added standard HTTP `429` responses with `Retry-After` and a dedicated WebSocket close code for limited receivers.
- Bounded rate-limiter memory with least-recently-used client eviction and added fail-fast environment configuration validation.
- Added an explicit WebSocket close frame when receiver authentication times out.
- Added rate-limit security, refill, memory-bound, configuration, HTTP, and WebSocket regression tests.

## 0.3.0

- Made alert creation and receiver delivery authorization atomic before fanout.
- Added bounded concurrent WebSocket fanout so slow receivers do not delay healthy ones.
- Added durable stop replay and receiver-side cancellation during audio preparation.
- Moved SQLite and credential work off the asyncio event loop.
- Added ongoing heartbeat-based clock calibration and bounded reconnect backoff.
- Added indexed enrollment-code lookup and rollback-compatible high-entropy token hashes.
- Added database-aware health checks, request correlation, timing headers, and critical-event logs.
- Added visible keyboard focus, reduced-motion support, status semantics, and duplicate-dispatch prevention.
- Updated FastAPI, migrated tests to HTTPX2, added vulnerability auditing, dependency automation, Python 3.10/3.12 CI, wheel checks, and JavaScript syntax checks.
- Hardened the container with a non-root runtime user and health check.
