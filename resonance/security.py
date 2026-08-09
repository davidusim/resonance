"""Small, dependency-free credential helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

PBKDF2_ITERATIONS = 310_000


def generate_secret(bytes_count: int = 32) -> str:
    return secrets.token_urlsafe(bytes_count)


def generate_enrollment_code() -> str:
    # Ten unambiguous characters provide about 50 bits for a short-lived, one-time code.
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2))


def hash_secret(secret: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.urlsafe_b64encode(salt).decode(),
        base64.urlsafe_b64encode(digest).decode(),
    )


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(raw_iterations)
        salt = base64.urlsafe_b64decode(raw_salt.encode())
        expected = base64.urlsafe_b64decode(raw_digest.encode())
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iterations)
    return hmac.compare_digest(actual, expected)


def normalize_enrollment_code(code: str) -> str:
    compact = "".join(character for character in code.upper() if character.isalnum())
    return compact


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())
