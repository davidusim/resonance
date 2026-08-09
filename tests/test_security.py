from resonance.security import (
    enrollment_code_lookup,
    generate_enrollment_code,
    hash_device_secret,
    hash_secret,
    normalize_enrollment_code,
    verify_secret,
)


def test_secret_hash_round_trip() -> None:
    encoded = hash_secret("correct horse battery staple", iterations=1_000)

    assert "correct horse battery staple" not in encoded
    assert verify_secret("correct horse battery staple", encoded)
    assert not verify_secret("wrong", encoded)


def test_enrollment_code_is_unambiguous_and_normalized() -> None:
    code = generate_enrollment_code()

    assert len(code) == 11
    assert code[5] == "-"
    assert normalize_enrollment_code(code.lower()) == code.replace("-", "")
    assert enrollment_code_lookup(code.lower()) == enrollment_code_lookup(code)


def test_generated_device_secret_uses_fast_high_entropy_hash() -> None:
    encoded = hash_device_secret("generated-random-device-token")

    assert encoded.startswith("sha256$")
    assert verify_secret("generated-random-device-token", encoded)
    assert not verify_secret("wrong", encoded)
