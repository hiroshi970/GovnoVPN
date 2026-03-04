"""
Application settings persistence for GovnoVPN.

Stores user preferences such as streamer mode, theme, auth server URL, etc.
"""

import json
from pathlib import Path
from typing import Any, Dict


_DEFAULTS: Dict[str, Any] = {
    "streamer_mode": False,
    "auth_server_url": "",
    "auth_remember": True,
    "theme": "system",
    "color_theme": "blue",
}


class AppSettings:
    """Simple key/value settings backed by a JSON file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._data: Dict[str, Any] = dict(_DEFAULTS)
        self._load()

    # ------------------------------------------------------------------
    # Generic get / set
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, _DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._save()

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def streamer_mode(self) -> bool:
        return bool(self._data.get("streamer_mode", False))

    @streamer_mode.setter
    def streamer_mode(self, value: bool) -> None:
        self._data["streamer_mode"] = value
        self._save()

    @property
    def auth_server_url(self) -> str:
        return self._data.get("auth_server_url", "")

    @auth_server_url.setter
    def auth_server_url(self, value: str) -> None:
        self._data["auth_server_url"] = value
        self._save()

    @property
    def auth_remember(self) -> bool:
        return bool(self._data.get("auth_remember", True))

    @auth_remember.setter
    def auth_remember(self, value: bool) -> None:
        self._data["auth_remember"] = value
        self._save()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text("utf-8"))
            self._data.update(raw)
        except Exception:
            pass

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            "utf-8",
        )
