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

Receiver secrets are randomly generated, stored only as PBKDF2-HMAC-SHA256 hashes on the coordinator, and transmitted only at initial enrollment. Audio is SHA-256 checked before playback. These controls do not replace TLS, endpoint security, network segmentation, or an incident-response plan.

Receiver status receipts are authenticated to an enrolled device identity, but they are operational telemetry rather than proof that a physical speaker emitted audible sound. Continue to test the complete device-to-speaker path during drills.
