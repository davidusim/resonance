# Security policy

## Supported version

The latest commit on `main` is supported while the project is pre-1.0.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature rather than opening a public issue. Include the affected endpoint, reproduction steps, impact, and any suggested mitigation.

## Deployment expectations

- Use HTTPS/WSS for every deployment beyond a loopback-only development machine.
- Put the coordinator behind a firewall or private network; expose only the receiver URL that participants need.
- Set a unique `RESONANCE_ADMIN_TOKEN` through a secret manager and rotate it after suspected exposure.
- Keep the generated SQLite database, `admin.token`, and uploaded audio outside source control.
- Enroll only devices controlled by participating organizations or people, and revoke devices that leave the response group.
- Do not modify Resonance to bypass Bluetooth pairing, operating-system consent, browser audio activation, or access controls.

Receiver secrets are randomly generated with 256 bits of source entropy. A secret is returned to its browser only during enrollment and is subsequently presented back to the coordinator over authenticated socket and media requests. The coordinator retains a salted PBKDF2-HMAC-SHA256 verifier for rollback compatibility and uses a separate SHA-256 token hash for routine authentication; a fast hash is appropriate here because these are generated tokens rather than human-chosen passwords. One-time enrollment codes retain PBKDF2 verification and use an indexed digest only to locate the candidate row without an unbounded scan. Audio is SHA-256 checked before playback. These controls do not replace TLS, endpoint security, network segmentation, rate limiting at the trusted reverse proxy, or an incident-response plan.

Receiver status receipts are authenticated to an enrolled device identity, but they are operational telemetry rather than proof that a physical speaker emitted audible sound. Continue to test the complete device-to-speaker path during drills.

Resonance is designed for a single process and single replica. Deploying multiple workers without a shared fanout/presence layer can silently omit receivers from an alert. See [the operations runbook](docs/OPERATIONS.md) before production use.
