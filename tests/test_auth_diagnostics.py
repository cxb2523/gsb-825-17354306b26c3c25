"""Tests for the offline auth-startup diagnostics.

Every fixture here is local: records are built in memory, the credential
is a fake that never touches the network, and ``_load_auth_record`` is
patched so no real ``auth_record.json``, keychain, or cache directory is
ever read. Each diagnostic assertion is paired with the real
``try_cached_token``/``get_credential`` behaviour under the same inputs,
so the report cannot drift from what startup actually does.
"""

import json
from unittest.mock import patch

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import AuthenticationRecord, DeviceCodeCredential

from outlook_mcp import auth as auth_module
from outlook_mcp.auth import AuthManager
from outlook_mcp.auth_diagnostics import (
    RefreshOutcome,
    diagnose_auth_startup,
)
from outlook_mcp.config import Config
from outlook_mcp.errors import (
    AccountMismatchError,
    AuthRequiredError,
    ClientIdMismatchError,
    StaleConsentError,
    UnencryptedTokenCacheError,
)


class _FakeCredential:
    """Stands in for DeviceCodeCredential: serves .default, touches nothing."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.requested_scopes: list[tuple[str, ...]] = []

    def get_token(self, *scopes):
        self.requested_scopes.append(scopes)
        return AccessToken("fake-token", 0)


def _record(client_id: str = "test-id", username: str = "user@example.com"):
    return AuthenticationRecord(
        tenant_id="consumers",
        client_id=client_id,
        authority="https://login.microsoftonline.com/consumers",
        home_account_id="home-1",
        username=username,
    )


def _run_real_startup(config: Config, record) -> tuple[AuthManager, bool]:
    """The real try_cached_token, with disk and network kept out of it."""
    auth = AuthManager(config)
    with (
        patch("outlook_mcp.auth._load_auth_record", return_value=record),
        patch("outlook_mcp.auth._unencrypted_fallback_will_be_used", return_value=False),
        patch("outlook_mcp.auth.DeviceCodeCredential", _FakeCredential),
    ):
        result = auth.try_cached_token()
    return auth, result


def _check(diag: dict, name: str) -> dict:
    return next(c for c in diag["checks"] if c["name"] == name)


class TestHappyPath:
    """Default config, a matching record, a successful refresh."""

    def test_scopes_equal_get_scopes_and_every_check_passes(self):
        config = Config(client_id="test-id", expected_username="user@example.com")
        record = _record()

        diag = diagnose_auth_startup(config, record, RefreshOutcome.SUCCESS)

        assert [e["scope"] for e in diag["consent_scopes"]] == AuthManager(config).get_scopes()
        assert all(e["source"] == "default_readwrite_set" for e in diag["consent_scopes"])
        assert diag["refresh_scope"] == auth_module.GRAPH_DEFAULT_SCOPE
        assert diag["record_present"] is True
        assert diag["username_matches"] is True
        assert diag["client_id_matches"] is True
        assert diag["checks"], "the check list must not be empty"
        assert all(c["passed"] is True for c in diag["checks"])
        assert diag["expected_error"] is None
        assert diag["error_origin"] is None

        # The real startup agrees: authenticated, and get_credential does not raise.
        auth, result = _run_real_startup(config, record)
        assert result is True
        assert auth.startup_error is None
        auth.get_credential()

    def test_the_outcome_accepts_a_plain_string(self):
        config = Config(client_id="test-id")
        diag = diagnose_auth_startup(config, _record(), "success")
        assert diag["expected_error"] is None
        assert all(c["passed"] is True for c in diag["checks"])

    def test_read_only_alone_does_not_narrow_the_consent(self):
        """read_only gates the tools, not the token — sources stay 'default'."""
        config = Config(client_id="test-id", read_only=True)
        diag = diagnose_auth_startup(config, _record(), RefreshOutcome.SUCCESS)
        assert [e["scope"] for e in diag["consent_scopes"]] == auth_module.SCOPES_READWRITE
        assert all(e["source"] == "default_readwrite_set" for e in diag["consent_scopes"])


class TestClientIdMismatch:
    CONFIGURED = "11111111-aaaa-4bbb-8ccc-000000000001"
    OTHER = "99999999-aaaa-4bbb-8ccc-000000000009"

    def test_mismatch_fails_the_check_with_client_id_mismatch_error(self):
        config = Config(client_id=self.CONFIGURED)
        record = _record(client_id=self.OTHER)

        diag = diagnose_auth_startup(config, record, RefreshOutcome.CLIENT_ID_MISMATCH)

        assert diag["client_id_matches"] is False
        check = _check(diag, "client_id_matches")
        assert check["passed"] is False
        assert check["error_type"] == "ClientIdMismatchError"
        assert "no credential is built" in check["reason"]
        assert diag["expected_error"] == "ClientIdMismatchError"
        # The mismatch stops startup before any refresh-stage check runs.
        names = [c["name"] for c in diag["checks"]]
        for later in names[names.index("client_id_matches") + 1 :]:
            assert _check(diag, later)["passed"] is None

        # The real startup raises exactly the type the diagnostic names.
        auth, result = _run_real_startup(config, record)
        assert result is False
        assert type(auth.startup_error).__name__ == diag["expected_error"]
        with pytest.raises(ClientIdMismatchError):
            auth.get_credential()

    def test_a_case_only_difference_is_the_same_app(self):
        config = Config(client_id="ABCDEF00-AAAA-4BBB-8CCC-000000000001")
        record = _record(client_id="abcdef00-aaaa-4bbb-8ccc-000000000001")

        diag = diagnose_auth_startup(config, record, RefreshOutcome.SUCCESS)

        assert diag["client_id_matches"] is True
        assert _check(diag, "client_id_matches")["passed"] is True
        assert diag["expected_error"] is None

        auth, result = _run_real_startup(config, record)
        assert result is True
        assert auth.startup_error is None


class TestScopeSources:
    def test_no_record_needs_an_interactive_login(self):
        config = Config(client_id="test-id")

        diag = diagnose_auth_startup(config, None, RefreshOutcome.NO_RECORD)

        assert diag["record_present"] is False
        assert diag["username_matches"] is None
        assert diag["client_id_matches"] is None
        check = _check(diag, "record_present")
        assert check["passed"] is False
        assert check["error_type"] == "AuthRequiredError"
        assert "interactive login" in check["reason"]
        assert diag["expected_error"] == "AuthRequiredError"

        # Real: no record on disk → try_cached_token False, no startup_error,
        # and get_credential raises the error the diagnostic named.
        auth = AuthManager(config)
        with patch("outlook_mcp.auth._load_auth_record", return_value=None):
            assert auth.try_cached_token() is False
        assert auth.startup_error is None
        with pytest.raises(AuthRequiredError):
            auth.get_credential()

    def test_read_only_consent_narrows_the_whole_list(self):
        config = Config(client_id="test-id", read_only=True, read_only_consent=True)

        diag = diagnose_auth_startup(config, _record(), RefreshOutcome.SUCCESS)

        assert [e["scope"] for e in diag["consent_scopes"]] == AuthManager(config).get_scopes()
        assert [e["scope"] for e in diag["consent_scopes"]] == auth_module.SCOPES_READONLY
        assert all(
            e["source"] == "read_only_consent_narrowing" for e in diag["consent_scopes"]
        )

    def test_mailbox_settings_write_replaces_one_scope(self):
        config = Config(client_id="test-id", mailbox_settings_write=True)

        diag = diagnose_auth_startup(config, _record(), RefreshOutcome.SUCCESS)

        assert [e["scope"] for e in diag["consent_scopes"]] == AuthManager(config).get_scopes()
        by_scope = {e["scope"]: e["source"] for e in diag["consent_scopes"]}
        assert by_scope["MailboxSettings.ReadWrite"] == "mailbox_settings_write_replacement"
        assert "MailboxSettings.Read" not in by_scope
        others = [s for scope, s in by_scope.items() if scope != "MailboxSettings.ReadWrite"]
        assert others and all(s == "default_readwrite_set" for s in others)


class TestRefreshFailureMapping:
    """Each refresh outcome maps to the error the real startup surfaces."""

    def test_aadsts70000_maps_to_stale_consent(self):
        config = Config(client_id="test-id")
        record = _record()

        diag = diagnose_auth_startup(config, record, RefreshOutcome.AADSTS70000)

        check = _check(diag, "consent_not_stale")
        assert check["passed"] is False
        assert check["error_type"] == "StaleConsentError"
        assert diag["expected_error"] == "StaleConsentError"
        assert _check(diag, "token_cache_storeable")["passed"] is True
        assert _check(diag, "refresh_succeeded")["passed"] is None  # never reached

        # Real: the same refusal injected on a real credential's token path.
        refusal = ClientAuthenticationError(
            "Authentication failed: AADSTS70000: The requested user must first "
            "sign-in and grant the client application access."
        )
        auth = AuthManager(config)
        with (
            patch("outlook_mcp.auth._load_auth_record", return_value=record),
            patch("outlook_mcp.auth._unencrypted_fallback_will_be_used", return_value=False),
            patch.object(DeviceCodeCredential, "_get_app", side_effect=refusal),
        ):
            assert auth.try_cached_token() is False
        assert type(auth.startup_error).__name__ == diag["expected_error"]
        with pytest.raises(StaleConsentError):
            auth.get_credential()

    def test_unencrypted_refusal_maps_to_unencrypted_token_cache(self):
        config = Config(client_id="test-id")
        record = _record()

        diag = diagnose_auth_startup(config, record, RefreshOutcome.UNENCRYPTED_CACHE_REFUSAL)

        check = _check(diag, "token_cache_storeable")
        assert check["passed"] is False
        assert check["error_type"] == "UnencryptedTokenCacheError"
        assert diag["expected_error"] == "UnencryptedTokenCacheError"
        # This one try_cached_token raises itself, not via get_credential.
        assert diag["error_origin"] == "try_cached_token"

        auth = AuthManager(config)
        with (
            patch("outlook_mcp.auth._load_auth_record", return_value=record),
            patch("outlook_mcp.auth._unencrypted_fallback_will_be_used", return_value=True),
            pytest.raises(UnencryptedTokenCacheError),
        ):
            auth.try_cached_token()

    def test_an_ordinary_failure_maps_to_auth_required(self):
        config = Config(client_id="test-id")
        record = _record()

        diag = diagnose_auth_startup(config, record, RefreshOutcome.EXPIRED)

        check = _check(diag, "refresh_succeeded")
        assert check["passed"] is False
        assert check["error_type"] == "AuthRequiredError"
        assert diag["expected_error"] == "AuthRequiredError"
        assert diag["error_origin"] == "get_credential"

        expired = ClientAuthenticationError(
            "Authentication failed: AADSTS7000215: Invalid grant. The token is expired."
        )
        auth = AuthManager(config)
        with (
            patch("outlook_mcp.auth._load_auth_record", return_value=record),
            patch("outlook_mcp.auth._unencrypted_fallback_will_be_used", return_value=False),
            patch.object(DeviceCodeCredential, "_get_app", side_effect=expired),
        ):
            assert auth.try_cached_token() is False
        assert auth.startup_error is None
        with pytest.raises(AuthRequiredError):
            auth.get_credential()

    def test_account_mismatch_maps_to_account_mismatch_error(self):
        config = Config(client_id="test-id", expected_username="alice@example.com")
        record = _record(username="bob@example.com")

        diag = diagnose_auth_startup(config, record, RefreshOutcome.ACCOUNT_MISMATCH)

        assert diag["username_matches"] is False
        check = _check(diag, "account_matches")
        assert check["passed"] is False
        assert check["error_type"] == "AccountMismatchError"
        assert diag["expected_error"] == "AccountMismatchError"
        # The account check fires before the client_id check is ever reached.
        assert _check(diag, "client_id_matches")["passed"] is None

        auth, result = _run_real_startup(config, record)
        assert result is False
        assert type(auth.startup_error).__name__ == diag["expected_error"]
        with pytest.raises(AccountMismatchError):
            auth.get_credential()


class TestReportShape:
    @pytest.mark.parametrize("outcome", list(RefreshOutcome))
    def test_every_outcome_is_json_serializable(self, outcome):
        config = Config(client_id="test-id", expected_username="user@example.com")
        json.dumps(diagnose_auth_startup(config, _record(), outcome))
        json.dumps(diagnose_auth_startup(config, None, outcome))

    def test_the_report_carries_no_record_content(self):
        """Only metadata: no username, home_account_id, or record text leaks."""
        config = Config(client_id="test-id", expected_username="user@example.com")
        diag = diagnose_auth_startup(config, _record(), RefreshOutcome.SUCCESS)
        payload = json.dumps(diag)
        assert "user@example.com" not in payload
        assert "home-1" not in payload
        assert "test-id" not in payload
