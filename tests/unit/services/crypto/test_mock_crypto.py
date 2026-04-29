from app.services.crypto.mock_crypto_service import MockCryptoService


def test_health_check_is_always_true() -> None:
    assert MockCryptoService().health_check() is True


def test_get_public_key_returns_sentinel() -> None:
    assert MockCryptoService().get_public_key("any") == "no-key"


def test_generate_keys_returns_none() -> None:
    MockCryptoService().generate_keys()


def test_decrypt_jwe_round_trips_input() -> None:
    assert MockCryptoService().decrypt_jwe("token", "kid") == b"token"


def test_decrypt_jwe_payload_returns_canned_subject() -> None:
    payload = MockCryptoService().decrypt_jwe_payload("token")
    assert isinstance(payload, dict)
    assert payload["subject"].startswith("pseudonym:eval:")


def test_hash_is_identity() -> None:
    assert MockCryptoService().hash(b"abc") == b"abc"
