"""Unit tests for Phase 15 JWT Authentication and Authorization."""

from __future__ import annotations

from datetime import timedelta
import jwt
import pytest

from core.security import create_access_token, decode_access_token, hash_password, verify_password


class TestJWTAuth:
    def test_token_creation_and_decoding(self) -> None:
        token = create_access_token(
            subject="analyst_jane",
            role="analyst",
            secret_key="test-secret-key",
        )
        assert isinstance(token, str)

        payload = decode_access_token(token, secret_key="test-secret-key")
        assert payload.sub == "analyst_jane"
        assert payload.role == "analyst"

    def test_invalid_signature_raises(self) -> None:
        token = create_access_token(
            subject="hacker",
            role="admin",
            secret_key="real-secret",
        )
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(token, secret_key="wrong-secret")

    def test_expired_token_raises(self) -> None:
        token = create_access_token(
            subject="expired_user",
            role="reader",
            secret_key="secret",
            expires_delta=timedelta(seconds=-10),
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_access_token(token, secret_key="secret")


class TestPasswordHashing:
    def test_correct_password_verifies(self) -> None:
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_hash_is_salted_and_not_plaintext(self) -> None:
        hashed = hash_password("my-secret-password")
        assert "my-secret-password" not in hashed
        # Hashing the same password twice must yield different hashes (random salt).
        assert hash_password("my-secret-password") != hashed

    def test_malformed_hash_fails_closed(self) -> None:
        assert verify_password("anything", "not-a-real-hash") is False
