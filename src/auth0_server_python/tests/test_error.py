"""Tests for the error module's typed exceptions."""

import pytest

from auth0_server_python.error import (
    Auth0Error,
    EnterpriseConnectError,
    EnterpriseConnectErrorCode,
    PasskeyError,
    PasskeyErrorCode,
)

# === Enterprise Connect ===


def test_enterprise_connect_error_is_auth0_error():
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.NOT_SUPPORTED, "no session in enterprise connect mode"
    )
    assert isinstance(err, Auth0Error)


def test_enterprise_connect_error_sets_code_name_and_message():
    err = EnterpriseConnectError(EnterpriseConnectErrorCode.NOT_SUPPORTED, "not supported")
    assert err.code == EnterpriseConnectErrorCode.NOT_SUPPORTED
    assert err.name == "EnterpriseConnectError"
    assert err.message == "not supported"
    assert err.cause is None


def test_enterprise_connect_error_preserves_cause():
    cause = ValueError("boom")
    err = EnterpriseConnectError(
        EnterpriseConnectErrorCode.NOT_SUPPORTED, "wrapped", cause=cause
    )
    assert err.cause is cause


def test_enterprise_connect_error_code_is_stable():
    assert EnterpriseConnectErrorCode.NOT_SUPPORTED == "enterprise_connect_not_supported"


# === Passkey ===


def test_passkey_error_retry_details_default_to_none():
    err = PasskeyError("passkey_token_error", "failed")
    assert err.auth_session is None
    assert err.verification_required is None
    assert err.is_verification_retryable is False


def test_passkey_error_keeps_cause_as_third_positional_argument():
    cause = ValueError("boom")
    err = PasskeyError("passkey_token_error", "failed", cause)
    assert err.cause is cause


def test_passkey_error_invalid_grant_with_auth_session_is_verification_retryable():
    err = PasskeyError(
        "invalid_grant", "failed", auth_session="session_abc123", verification_required=["email"]
    )
    assert err.is_verification_retryable is True
    assert err.verification_required == ["email"]


@pytest.mark.parametrize(
    ("code", "auth_session"),
    [
        ("invalid_grant", None),
        ("invalid_grant", ""),
        ("invalid_request", None),
        ("invalid_request", "session_abc123"),
        ("server_error", None),
    ],
)
def test_passkey_error_other_failures_are_not_verification_retryable(code, auth_session):
    err = PasskeyError(code, "failed", auth_session=auth_session)
    assert err.is_verification_retryable is False


def test_passkey_error_str_and_repr_do_not_contain_auth_session():
    err = PasskeyError("invalid_grant", "failed", auth_session="session_abc123")
    assert "session_abc123" not in str(err)
    assert "session_abc123" not in repr(err)


def test_passkey_error_code_too_many_requests_value():
    assert PasskeyErrorCode.TOO_MANY_REQUESTS == "too_many_requests"
