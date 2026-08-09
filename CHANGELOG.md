# Changelog

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
