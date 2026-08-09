from resonance.security import (
    generate_enrollment_code,
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
