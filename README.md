# Resonance

Resonance is a consent-based emergency audio coordinator. It schedules the same verified audio on enrolled receiver devices, each of which plays through its selected system output—including a Bluetooth speaker that the device owner has already paired.

It is intentionally **not** a Bluetooth takeover tool. Bluetooth pairing, operating-system permission, browser audio activation, and device consent are security boundaries. Resonance does not bypass them and cannot make an ordinary speaker accept an unauthenticated source.

## How it works

1. An operator starts the coordinator and opens `/admin`.
2. The operator creates a short-lived, single-use enrollment code.
3. A participant opens the receiver page on a phone, tablet, laptop, or small computer, enters the code, and taps once to enable audio.
4. The receiver uses that device's current system audio route. A Bluetooth speaker can be selected through normal system settings.
5. The operator uploads an audio file and dispatches it. Connected receivers verify its SHA-256 hash, buffer it, and schedule playback against the coordinator clock.

```text
                         authenticated WebSocket
  Coordinator /admin  ─────────────────────────────► enrolled receiver A ─► paired speaker
          │             scheduled alert + SHA-256  ► enrolled receiver B ─► paired speaker
          └── SQLite audit/device/track metadata   ► enrolled receiver C ─► built-in audio
```

## Features

- One-time enrollment codes with configurable expiration
- Random per-receiver credentials; only PBKDF2 hashes are stored server-side
- Immediate receiver revocation and socket disconnect
- Authenticated audio downloads with receiver-side SHA-256 verification
- WebSocket dispatch with a shared future start time and client clock-offset sampling
- Synchronized stop signal
- SQLite device, track, alert, and audit metadata
- Responsive coordinator and receiver web interfaces
- Security headers, upload size/type limits, no third-party browser assets

## Quick start

Python 3.10 or newer is required.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
$env:RESONANCE_ADMIN_TOKEN = "replace-with-a-random-secret-at-least-24-characters"
python -m resonance.main
```

Open `http://localhost:8080/admin` on the coordinator. The receiver page is `http://localhost:8080/`.

If `RESONANCE_ADMIN_TOKEN` is omitted, Resonance generates one, prints it once, and saves it to `data/admin.token`. Runtime data is under `data/` by default and is ignored by Git.

Run checks with:

```powershell
ruff check .
ruff format --check .
pytest -q
```

## Docker

```powershell
docker build -t resonance-alert .
docker run --rm -p 8080:8080 -v resonance-data:/data `
  -e RESONANCE_ADMIN_TOKEN="replace-with-a-long-random-secret" resonance-alert
```

## Production checklist

- Serve the app behind HTTPS. Modern browsers require a secure context for several media APIs, and device secrets must never travel over plaintext networks.
- Put the coordinator on a trusted/private network where possible.
- Use a strong admin token from a secret manager and restrict `/admin` at the reverse proxy or VPN.
- Keep receiver devices powered, the page open, audio enabled, and the desired speaker paired and selected.
- Test every receiver and speaker as part of scheduled drills. Browser scheduling reduces skew but this is not a life-safety-certified alarm system.
- Maintain a separate certified emergency notification path. Network loss, battery failure, browser suspension, Bluetooth interference, and device power management can all prevent playback.
- Get organizational and participant approval before enrollment. Follow local emergency communications, accessibility, privacy, and radio regulations.

See [SECURITY.md](SECURITY.md) for operational security guidance.

## Important platform limits

Ordinary Bluetooth speakers are audio peripherals, not general-purpose network receivers. They usually accept one paired audio source at a time and deliberately require a user-approved pairing handshake. A coordinator also cannot force arbitrary phones or laptops to route audio or ignore their OS controls. The receiver-per-output design is the interoperable path: consent and pairing happen during setup, before a crisis.

Synchronization is best-effort. Each browser estimates its offset from the coordinator, downloads and verifies the audio, decodes it, then schedules it on the Web Audio clock. Real-world skew depends on network delay, browser scheduling, Bluetooth codec buffers, and speaker firmware.

## License

MIT
