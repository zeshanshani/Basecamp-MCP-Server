"""
OAuth 2.1 authorisation server for the MCP transport.

Implements the OAuthAuthorizationServerProvider protocol from the MCP SDK
so that Claude.ai (and any other MCP client) can complete a standard OAuth
flow against this server instead of using a pre-shared bearer token.

State is persisted to a JSON file on disk (the Railway volume) so issued
tokens survive container restarts. The authorisation step delegates the
human-approval moment to a Flask consent screen, which lives in oauth_app.py
behind the existing HTTP Basic Auth gate.

Storage layout (single JSON file):

    {
      "clients":              {client_id: OAuthClientInformationFull, ...},
      "pending_authorisations": {pending_id: {client_id, state, scopes,
                                              code_challenge, redirect_uri,
                                              redirect_uri_provided_explicitly,
                                              resource, expires_at}, ...},
      "auth_codes":            {code: AuthorizationCode, ...},
      "access_tokens":         {token: AccessToken, ...},
      "refresh_tokens":        {token: RefreshToken, ...}
    }
"""

import asyncio
import json
import logging
import os
import secrets
import time
from typing import Any
from urllib.parse import urlencode

from pydantic import AnyUrl
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

DEFAULT_STATE_FILE = "/data/mcp_oauth_state.json"

# Token / code lifetimes.
PENDING_AUTHORISATION_TTL = 10 * 60         # 10 min — covers a slow consent screen
AUTH_CODE_TTL = 60                          # 1 min — codes are exchanged immediately
ACCESS_TOKEN_TTL = 60 * 60                  # 1 hour — refreshed via refresh_token
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30       # 30 days — long-lived, rotated on use


def _now() -> int:
    return int(time.time())


def _empty_state() -> dict[str, dict[str, Any]]:
    return {
        "clients": {},
        "pending_authorisations": {},
        "auth_codes": {},
        "access_tokens": {},
        "refresh_tokens": {},
    }


class FileOAuthProvider(OAuthAuthorizationServerProvider):
    """
    Single-tenant OAuth 2.1 authorisation server.

    "Single-tenant" because there is only one end user (the deployment owner).
    Anyone who can complete the consent flow is treated as that user — the
    consent screen sits behind the same HTTP Basic Auth gate as the rest of
    the admin UI.
    """

    def __init__(self, state_file: str, consent_url_base: str):
        self._state_file = state_file
        self._consent_url_base = consent_url_base.rstrip("/")
        self._lock = asyncio.Lock()
        os.makedirs(os.path.dirname(state_file) or ".", exist_ok=True)
        if not os.path.exists(state_file):
            self._write(_empty_state())

    # ---------------------------------------------------------------- storage

    def _read(self) -> dict[str, Any]:
        try:
            with open(self._state_file, "r") as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return _empty_state()
        # Ensure all top-level buckets exist after a schema bump.
        for k, v in _empty_state().items():
            data.setdefault(k, v)
        return data

    def _write(self, data: dict[str, Any]) -> None:
        tmp = self._state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, self._state_file)
        try:
            os.chmod(self._state_file, 0o600)
        except OSError:
            pass

    # --------------------------------------------------------------- clients

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        async with self._lock:
            data = self._read()
            raw = data["clients"].get(client_id)
        if raw is None:
            return None
        return OAuthClientInformationFull.model_validate(raw)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        async with self._lock:
            data = self._read()
            assert client_info.client_id is not None
            data["clients"][client_info.client_id] = json.loads(
                client_info.model_dump_json(exclude_none=True)
            )
            self._write(data)
        logger.info("Registered OAuth client: %s", client_info.client_id)

    # ------------------------------------------------------------ authorize

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """
        Stash the request and return a URL the user's browser will follow to a
        consent screen. The consent screen completes the authorisation by
        issuing a code and redirecting back to the client's redirect_uri.
        """
        pending_id = secrets.token_urlsafe(24)
        async with self._lock:
            data = self._read()
            data["pending_authorisations"][pending_id] = {
                "client_id": client.client_id,
                "state": params.state,
                "scopes": params.scopes,
                "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "resource": params.resource,
                "expires_at": _now() + PENDING_AUTHORISATION_TTL,
            }
            self._write(data)
        return f"{self._consent_url_base}/oauth/consent?{urlencode({'pending_id': pending_id})}"

    # ----------------------------- consent screen entry points (sync helpers)
    # These are called from Flask, which runs synchronously in WSGI workers.
    # They use the same JSON file but skip the async lock — Flask requests are
    # serialised through Werkzeug/WSGI and a single uvicorn worker.

    def get_pending(self, pending_id: str) -> dict[str, Any] | None:
        data = self._read()
        record = data["pending_authorisations"].get(pending_id)
        if record is None:
            return None
        if record["expires_at"] < _now():
            data["pending_authorisations"].pop(pending_id, None)
            self._write(data)
            return None
        return record

    def approve_pending(self, pending_id: str) -> tuple[str, str | None, dict[str, Any]] | None:
        """
        Issue an authorisation code for the pending request and remove the
        pending record. Returns (auth_code, state, pending_record) or None if
        the pending id is unknown/expired.
        """
        data = self._read()
        pending = data["pending_authorisations"].pop(pending_id, None)
        if pending is None or pending["expires_at"] < _now():
            self._write(data)
            return None
        code = secrets.token_urlsafe(32)
        data["auth_codes"][code] = {
            "code": code,
            "client_id": pending["client_id"],
            "scopes": pending.get("scopes") or [],
            "code_challenge": pending["code_challenge"],
            "redirect_uri": pending["redirect_uri"],
            "redirect_uri_provided_explicitly": pending["redirect_uri_provided_explicitly"],
            "expires_at": _now() + AUTH_CODE_TTL,
            "resource": pending.get("resource"),
        }
        self._write(data)
        return code, pending.get("state"), pending

    def discard_pending(self, pending_id: str) -> dict[str, Any] | None:
        data = self._read()
        pending = data["pending_authorisations"].pop(pending_id, None)
        self._write(data)
        return pending

    # ----------------------------------------------------- auth code exchange

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        async with self._lock:
            data = self._read()
            raw = data["auth_codes"].get(authorization_code)
        if raw is None or raw["client_id"] != client.client_id:
            return None
        if raw["expires_at"] < _now():
            async with self._lock:
                data = self._read()
                data["auth_codes"].pop(authorization_code, None)
                self._write(data)
            return None
        return AuthorizationCode(
            code=raw["code"],
            scopes=raw["scopes"],
            expires_at=raw["expires_at"],
            client_id=raw["client_id"],
            code_challenge=raw["code_challenge"],
            redirect_uri=AnyUrl(raw["redirect_uri"]),
            redirect_uri_provided_explicitly=raw["redirect_uri_provided_explicitly"],
            resource=raw.get("resource"),
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        now = _now()
        async with self._lock:
            data = self._read()
            data["auth_codes"].pop(authorization_code.code, None)
            data["access_tokens"][access] = {
                "token": access,
                "client_id": client.client_id,
                "scopes": authorization_code.scopes,
                "expires_at": now + ACCESS_TOKEN_TTL,
                "resource": authorization_code.resource,
            }
            data["refresh_tokens"][refresh] = {
                "token": refresh,
                "client_id": client.client_id,
                "scopes": authorization_code.scopes,
                "expires_at": now + REFRESH_TOKEN_TTL,
            }
            self._write(data)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
            refresh_token=refresh,
        )

    # ----------------------------------------------------- refresh exchange

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        async with self._lock:
            data = self._read()
            raw = data["refresh_tokens"].get(refresh_token)
        if raw is None or raw["client_id"] != client.client_id:
            return None
        if raw.get("expires_at") is not None and raw["expires_at"] < _now():
            return None
        return RefreshToken(
            token=raw["token"],
            client_id=raw["client_id"],
            scopes=raw["scopes"],
            expires_at=raw.get("expires_at"),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotate both tokens on every refresh. The SDK's TokenHandler has
        # already validated that any requested scopes are a subset of those
        # originally granted, so we can use `scopes` (or fall back to the
        # ones the refresh token was issued with).
        granted_scopes = scopes or refresh_token.scopes
        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        now = _now()
        async with self._lock:
            data = self._read()
            data["refresh_tokens"].pop(refresh_token.token, None)
            data["access_tokens"][new_access] = {
                "token": new_access,
                "client_id": client.client_id,
                "scopes": granted_scopes,
                "expires_at": now + ACCESS_TOKEN_TTL,
                "resource": None,
            }
            data["refresh_tokens"][new_refresh] = {
                "token": new_refresh,
                "client_id": client.client_id,
                "scopes": granted_scopes,
                "expires_at": now + REFRESH_TOKEN_TTL,
            }
            self._write(data)
        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(granted_scopes) if granted_scopes else None,
            refresh_token=new_refresh,
        )

    # --------------------------------------------- access token verification

    async def load_access_token(self, token: str) -> AccessToken | None:
        async with self._lock:
            data = self._read()
            raw = data["access_tokens"].get(token)
        if raw is None:
            return None
        if raw.get("expires_at") is not None and raw["expires_at"] < _now():
            return None
        return AccessToken(
            token=raw["token"],
            client_id=raw["client_id"],
            scopes=raw["scopes"],
            expires_at=raw.get("expires_at"),
            resource=raw.get("resource"),
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        async with self._lock:
            data = self._read()
            data["access_tokens"].pop(token.token, None)
            data["refresh_tokens"].pop(token.token, None)
            self._write(data)
