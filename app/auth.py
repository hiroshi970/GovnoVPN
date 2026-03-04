"""
Authentication module for GovnoVPN.

Supports two modes:
  1. Token-based authentication
  2. Login + password authentication

Credentials are verified against a remote server.
Locally, the session is cached so the user doesn't have to log in every time.
"""

import json
import hashlib
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Tuple

import requests


@dataclass
class AuthSession:
    """Locally-persisted authentication session."""
    auth_type: str = ""          # "token" | "credentials"
    server_url: str = ""         # base URL of auth server
    token: str = ""              # token (if auth_type == "token")
    username: str = ""           # username (if auth_type == "credentials")
    # We never store the raw password — only a server-issued session token
    session_token: str = ""      # server-issued session token
    user_display: str = ""       # display name returned by server
    expires_at: float = 0.0      # UNIX timestamp when session expires (0 = no expiry)


class AuthManager:
    """Handles authentication against a remote server and local session caching."""

    # Default timeout for HTTP requests (seconds)
    _TIMEOUT = 15

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._session_path = data_dir / "auth_session.json"
        self._session: Optional[AuthSession] = None
        self._load_session()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_authenticated(self) -> bool:
        """Check if a valid (non-expired) session exists."""
        if self._session is None:
            return False
        if self._session.expires_at and time.time() > self._session.expires_at:
            self.logout()
            return False
        return bool(self._session.session_token)

    @property
    def session(self) -> Optional[AuthSession]:
        return self._session

    @property
    def display_name(self) -> str:
        if self._session:
            return self._session.user_display or self._session.username or "User"
        return ""

    def login_with_token(self, server_url: str, token: str) -> Tuple[bool, str]:
        """Authenticate using an API token.

        Returns (success, message).
        The server endpoint: POST <server_url>/auth/token
        Body: {"token": "<token>"}
        Expected response: {"success": bool, "message": str,
                            "session_token": str, "user": str, "expires_at": float}
        """
        server_url = server_url.rstrip("/")
        url = f"{server_url}/auth/token"
        try:
            resp = requests.post(
                url,
                json={"token": token},
                timeout=self._TIMEOUT,
            )
            return self._handle_auth_response(resp, server_url, auth_type="token", token=token)
        except requests.ConnectionError:
            return False, "Не удалось подключиться к серверу авторизации"
        except requests.Timeout:
            return False, "Сервер авторизации не отвечает (тайм-аут)"
        except Exception as exc:
            return False, f"Ошибка: {exc}"

    def login_with_credentials(self, server_url: str, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate using login + password.

        Returns (success, message).
        The server endpoint: POST <server_url>/auth/login
        Body: {"username": "<login>", "password": "<password>"}
        Expected response: same as token auth.
        """
        server_url = server_url.rstrip("/")
        url = f"{server_url}/auth/login"
        try:
            resp = requests.post(
                url,
                json={"username": username, "password": password},
                timeout=self._TIMEOUT,
            )
            return self._handle_auth_response(resp, server_url, auth_type="credentials", username=username)
        except requests.ConnectionError:
            return False, "Не удалось подключиться к серверу авторизации"
        except requests.Timeout:
            return False, "Сервер авторизации не отвечает (тайм-аут)"
        except Exception as exc:
            return False, f"Ошибка: {exc}"

    def verify_session(self) -> Tuple[bool, str]:
        """Re-verify the current session with the server.

        Endpoint: POST <server_url>/auth/verify
        Body: {"session_token": "<token>"}
        """
        if self._session is None:
            return False, "Нет активной сессии"

        server_url = self._session.server_url.rstrip("/")
        url = f"{server_url}/auth/verify"
        try:
            resp = requests.post(
                url,
                json={"session_token": self._session.session_token},
                timeout=self._TIMEOUT,
            )
            data = resp.json()
            if data.get("success"):
                return True, data.get("message", "OK")
            else:
                self.logout()
                return False, data.get("message", "Сессия недействительна")
        except Exception as exc:
            return False, f"Ошибка проверки: {exc}"

    def logout(self) -> None:
        """Clear local session data."""
        self._session = None
        if self._session_path.exists():
            try:
                self._session_path.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _handle_auth_response(
        self,
        resp: requests.Response,
        server_url: str,
        auth_type: str,
        token: str = "",
        username: str = "",
    ) -> Tuple[bool, str]:
        """Parse successful auth response and persist session."""
        try:
            if resp.status_code == 401:
                data = resp.json() if resp.text else {}
                return False, data.get("message", "Неверные учётные данные")
            if resp.status_code == 403:
                data = resp.json() if resp.text else {}
                return False, data.get("message", "Доступ запрещён")
            resp.raise_for_status()
            data = resp.json()
        except requests.HTTPError:
            return False, f"Ошибка сервера: HTTP {resp.status_code}"
        except (ValueError, KeyError):
            return False, "Некорректный ответ от сервера"

        if not data.get("success"):
            return False, data.get("message", "Авторизация не удалась")

        self._session = AuthSession(
            auth_type=auth_type,
            server_url=server_url,
            token=token,
            username=username,
            session_token=data.get("session_token", ""),
            user_display=data.get("user", username),
            expires_at=data.get("expires_at", 0.0),
        )
        self._save_session()
        return True, data.get("message", "Авторизация успешна")

    def _load_session(self) -> None:
        if not self._session_path.exists():
            return
        try:
            raw = json.loads(self._session_path.read_text("utf-8"))
            self._session = AuthSession(**{
                k: v for k, v in raw.items()
                if k in AuthSession.__dataclass_fields__
            })
            # Check expiry
            if self._session.expires_at and time.time() > self._session.expires_at:
                self.logout()
        except Exception:
            self._session = None

    def _save_session(self) -> None:
        if self._session is None:
            return
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._session_path.write_text(
            json.dumps(asdict(self._session), indent=2, ensure_ascii=False),
            "utf-8",
        )
