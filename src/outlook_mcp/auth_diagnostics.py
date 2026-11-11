"""Offline diagnostics for the authentication startup path.

Pure functions that mirror the decisions ``AuthManager`` makes at startup —
which scopes a first consent would ask for, which scope silent refresh
redeems, and which error a failed startup surfaces as — without touching
any of the machinery those decisions involve: no ``DeviceCodeCredential``
is built, no network is consulted, and ``auth_record.json`` is neither
read nor written. The caller supplies the record (or ``None``) and the
outcome of the most recent silent refresh attempt; the diagnostic combines
them with the config into a JSON-serializable report.

The report carries metadata only — booleans, scope names, check names and
error type names. No token, verifier, or record content is included, so
the report is safe to log or hand to an operator.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from azure.identity import AuthenticationRecord

from outlook_mcp.auth import GRAPH_DEFAULT_SCOPE, AuthManager
from outlook_mcp.config import Config
from outlook_mcp.errors import (
    AccountMismatchError,
    AuthRequiredError,
    ClientIdMismatchError,
    StaleConsentError,
    UnencryptedTokenCacheError,
)


class RefreshOutcome(str, Enum):
    """What the most recent silent refresh attempt did.

    The first three values describe an attempt that stopped before any
    token request ran; the rest describe the refresh itself. Plain strings
    equal to a value (``"success"``) are accepted anywhere the enum is.
    """

    SUCCESS = "success"
    EXPIRED = "expired"  # an ordinary refresh failure — stale token, revoked grant
    AADSTS70000 = "aadsts70000"  # the consent dead end (StaleConsentError)
    UNENCRYPTED_CACHE_REFUSAL = "unencrypted_cache_refusal"  # azure's plaintext refusal
    CLIENT_ID_MISMATCH = "client_id_mismatch"
    ACCOUNT_MISMATCH = "account_mismatch"
    NO_RECORD = "no_record"


class ScopeSource(str, Enum):
    """Why a scope is in the first-consent list."""

    DEFAULT_READWRITE_SET = "default_readwrite_set"
    READ_ONLY_CONSENT_NARROWING = "read_only_consent_narrowing"
    MAILBOX_SETTINGS_WRITE_REPLACEMENT = "mailbox_settings_write_replacement"


# Check names, in the order try_cached_token makes the underlying decisions.
# A check the startup path never reaches (an earlier one already failed)
# is reported with passed=None.
CHECK_CLIENT_ID_CONFIGURED = "client_id_configured"
CHECK_RECORD_PRESENT = "record_present"
CHECK_ACCOUNT_MATCHES = "account_matches"
CHECK_CLIENT_ID_MATCHES = "client_id_matches"
CHECK_TOKEN_CACHE_STOREABLE = "token_cache_storeable"
CHECK_CONSENT_NOT_STALE = "consent_not_stale"
CHECK_REFRESH_SUCCEEDED = "refresh_succeeded"

_CHECK_ORDER = [
    CHECK_CLIENT_ID_CONFIGURED,
    CHECK_RECORD_PRESENT,
    CHECK_ACCOUNT_MATCHES,
    CHECK_CLIENT_ID_MATCHES,
    CHECK_TOKEN_CACHE_STOREABLE,
    CHECK_CONSENT_NOT_STALE,
    CHECK_REFRESH_SUCCEEDED,
]


def _check(name: str, passed: bool, reason: str, error_type: str) -> dict[str, Any]:
    return {"name": name, "passed": passed, "reason": reason, "error_type": error_type}


def _passed(name: str) -> dict[str, Any]:
    return _check(name, True, None, None)


def _not_reached(name: str) -> dict[str, Any]:
    return _check(name, None, None, None)


def _username_matches(config: Config, record: AuthenticationRecord) -> bool:
    """Same comparison as ``AuthManager._account_matches``: caseless, no aliases."""
    expected = config.expected_username
    if expected is None:
        return True
    username = getattr(record, "username", None)
    return isinstance(username, str) and username.casefold() == expected.casefold()


def _client_id_matches(config: Config, record: AuthenticationRecord) -> bool:
    """Same comparison as ``try_cached_token``: case-insensitive, strings only.

    The real code only compares when the record carries a string client_id
    (anything else skips the check), and only after a configured client_id
    passed the first check — both are mirrored here.
    """
    saved = getattr(record, "client_id", None)
    if not isinstance(saved, str) or not config.client_id:
        return True
    return saved.lower() == config.client_id.lower()


def _consent_scopes(config: Config) -> list[dict[str, str]]:
    """The first-consent scope list, each entry annotated with its source.

    The list itself comes from ``AuthManager(config).get_scopes()`` so the
    diagnostic can never drift from what ``login_interactive`` would ask
    for; only the per-entry explanation is computed here.
    """
    scopes = AuthManager(config).get_scopes()
    if config.read_only_consent:
        sources = [ScopeSource.READ_ONLY_CONSENT_NARROWING.value] * len(scopes)
    elif config.mailbox_settings_write:
        sources = [
            ScopeSource.MAILBOX_SETTINGS_WRITE_REPLACEMENT.value
            if scope == "MailboxSettings.ReadWrite"
            else ScopeSource.DEFAULT_READWRITE_SET.value
            for scope in scopes
        ]
    else:
        sources = [ScopeSource.DEFAULT_READWRITE_SET.value] * len(scopes)
    return [{"scope": scope, "source": source} for scope, source in zip(scopes, sources)]


def diagnose_auth_startup(
    config: Config,
    record: AuthenticationRecord | None,
    refresh_outcome: RefreshOutcome | str,
) -> dict[str, Any]:
    """Diagnose what the auth startup path would do, without doing it.

    ``record`` is the saved AuthenticationRecord (or None when there is
    none); ``refresh_outcome`` is what the most recent silent refresh
    attempt did. The returned dict is JSON-serializable and contains no
    credential material — only scope names, booleans, check names and
    error type names.

    ``expected_error`` is the error type the startup sequence surfaces:
    raised by ``get_credential()`` after ``try_cached_token()`` returned
    False (``error_origin == "get_credential"``), or raised by
    ``try_cached_token()`` itself for the unencrypted-cache refusal,
    which that method re-raises instead of recording (``error_origin ==
    "try_cached_token"``). None on the success path, where neither raises.
    """
    outcome = RefreshOutcome(refresh_outcome)

    record_present = record is not None
    username_matches = _username_matches(config, record) if record_present else None
    client_id_matches = _client_id_matches(config, record) if record_present else None

    checks: list[dict[str, Any]] = []

    def _fail(name: str, reason: str, error_type: str) -> None:
        checks.append(_check(name, False, reason, error_type))
        # The startup path stops at the first failure, so every later check
        # is one it never reached.
        checks.extend(_not_reached(later) for later in _CHECK_ORDER[len(checks):])

    if not config.client_id:
        # try_cached_token returns False before even loading the record.
        _fail(
            CHECK_CLIENT_ID_CONFIGURED,
            "client_id is not configured; silent refresh is not attempted and "
            "every tool call raises this until `outlook-mcp auth` can run",
            AuthRequiredError.__name__,
        )
    elif not record_present:
        checks.append(_passed(CHECK_CLIENT_ID_CONFIGURED))
        _fail(
            CHECK_RECORD_PRESENT,
            "no saved authentication record; an interactive login "
            "(`outlook-mcp auth`) is required before silent refresh can succeed",
            AuthRequiredError.__name__,
        )
    else:
        checks.append(_passed(CHECK_CLIENT_ID_CONFIGURED))
        checks.append(_passed(CHECK_RECORD_PRESENT))
        if not username_matches:
            _fail(
                CHECK_ACCOUNT_MATCHES,
                "the record's username does not match expected_username "
                "(compared case-insensitively); the sign-in is not used",
                AccountMismatchError.__name__,
            )
        elif not client_id_matches:
            checks.append(_passed(CHECK_ACCOUNT_MATCHES))
            _fail(
                CHECK_CLIENT_ID_MATCHES,
                "the record was saved for a different app registration "
                "(client_id, compared case-insensitively); no credential is "
                "built from it — azure-identity would serve the record's "
                "client_id, not the configured one",
                ClientIdMismatchError.__name__,
            )
        else:
            checks.append(_passed(CHECK_ACCOUNT_MATCHES))
            checks.append(_passed(CHECK_CLIENT_ID_MATCHES))
            if outcome is RefreshOutcome.UNENCRYPTED_CACHE_REFUSAL:
                _fail(
                    CHECK_TOKEN_CACHE_STOREABLE,
                    "the environment refused to persist the token cache "
                    "(azure's allow_unencrypted_storage refusal): no encrypted "
                    "store is available and plaintext storage was not opted into",
                    UnencryptedTokenCacheError.__name__,
                )
            elif outcome is RefreshOutcome.AADSTS70000:
                checks.append(_passed(CHECK_TOKEN_CACHE_STOREABLE))
                _fail(
                    CHECK_CONSENT_NOT_STALE,
                    "the refresh was refused with AADSTS70000: this session "
                    "cannot grant the requested scopes, so no refresh from "
                    "this process can succeed — logging in again is the exit",
                    StaleConsentError.__name__,
                )
            elif outcome is RefreshOutcome.EXPIRED:
                checks.append(_passed(CHECK_TOKEN_CACHE_STOREABLE))
                checks.append(_passed(CHECK_CONSENT_NOT_STALE))
                _fail(
                    CHECK_REFRESH_SUCCEEDED,
                    "the silent refresh failed (an ordinary stale token); "
                    "re-running `outlook-mcp auth` restores it",
                    AuthRequiredError.__name__,
                )
            elif outcome is RefreshOutcome.SUCCESS:
                checks.append(_passed(CHECK_TOKEN_CACHE_STOREABLE))
                checks.append(_passed(CHECK_CONSENT_NOT_STALE))
                checks.append(_passed(CHECK_REFRESH_SUCCEEDED))
            else:
                # NO_RECORD / ACCOUNT_MISMATCH / CLIENT_ID_MISMATCH: the
                # attempt stopped before any refresh ran, yet the record
                # supplied here passed every pre-refresh check — there is
                # no refresh-stage result to report.
                checks.extend(_not_reached(name) for name in _CHECK_ORDER[len(checks):])

    expected_error = next(
        (check["error_type"] for check in checks if check["passed"] is False), None
    )
    if expected_error is None:
        error_origin = None
    elif expected_error == UnencryptedTokenCacheError.__name__:
        # try_cached_token re-raises this one itself rather than recording
        # it as the startup error — it is a config problem, not a stale token.
        error_origin = "try_cached_token"
    else:
        error_origin = "get_credential"

    return {
        "consent_scopes": _consent_scopes(config),
        "refresh_scope": GRAPH_DEFAULT_SCOPE,
        "record_present": record_present,
        "username_matches": username_matches,
        "client_id_matches": client_id_matches,
        "checks": checks,
        "expected_error": expected_error,
        "error_origin": error_origin,
    }
