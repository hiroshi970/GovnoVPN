"""
sing-box process manager — запуск, остановка, мониторинг ядра sing-box.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
import zipfile
import io
from pathlib import Path
from typing import Callable, Optional

import requests


SINGBOX_RELEASE_URL = (
    "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
)


def _data_dir() -> Path:
    """Return the platform-specific data directory for the app."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".local" / "share"
    d = base / "GovnoVPN"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _bin_name() -> str:
    return "sing-box.exe" if platform.system() == "Windows" else "sing-box"


class SingBoxManager:
    """Manages the sing-box binary and its lifecycle."""

    def __init__(self) -> None:
        self.data_dir = _data_dir()
        self.bin_path = self.data_dir / _bin_name()
        self.config_path = self.data_dir / "config.json"
        self._process: Optional[subprocess.Popen] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._on_status_change: Optional[Callable[[str], None]] = None
        self._on_log: Optional[Callable[[str], None]] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Binary management
    # ------------------------------------------------------------------

    def is_installed(self) -> bool:
        return self.bin_path.exists()

    def version(self) -> Optional[str]:
        if not self.is_installed():
            return None
        try:
            result = subprocess.run(
                [str(self.bin_path), "version"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            return result.stdout.strip().split("\n")[0] if result.returncode == 0 else None
        except Exception:
            return None

    def _parse_version(self, ver_str: Optional[str]) -> Optional[tuple]:
        """Extract (major, minor, patch) from a version string like 'sing-box version 1.12.0'."""
        if not ver_str:
            return None
        m = re.search(r'(\d+)\.(\d+)\.(\d+)', ver_str)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def latest_version(self) -> Optional[str]:
        """Fetch the latest release tag name from GitHub."""
        try:
            resp = requests.get(SINGBOX_RELEASE_URL, timeout=15)
            resp.raise_for_status()
            return resp.json().get("tag_name", "")
        except Exception:
            return None

    def check_update(self) -> tuple[bool, Optional[str], Optional[str]]:
        """Check if a newer version is available.
        Returns (update_available, local_version, remote_version).
        """
        local = self.version()
        remote = self.latest_version()
        local_t = self._parse_version(local)
        remote_t = self._parse_version(remote)
        if local_t and remote_t and remote_t > local_t:
            return True, local, remote
        return False, local, remote

    def download_latest(self, progress_cb: Optional[Callable[[float], None]] = None) -> bool:
        """Download the latest sing-box release from GitHub.
        ``progress_cb`` is called with a float 0..1 indicating progress.
        Returns True on success.
        """
        try:
            resp = requests.get(SINGBOX_RELEASE_URL, timeout=15)
            resp.raise_for_status()
            release = resp.json()

            # Determine the asset name we need
            system = platform.system().lower()
            arch = platform.machine().lower()
            if arch in ("x86_64", "amd64"):
                arch = "amd64"
            elif arch in ("aarch64", "arm64"):
                arch = "arm64"

            wanted_suffix = f"{system}-{arch}.zip"
            if system == "windows":
                wanted_suffix = f"windows-{arch}.zip"

            asset_url: Optional[str] = None
            for asset in release.get("assets", []):
                name: str = asset["name"]
                if name.endswith(wanted_suffix) and "sing-box" in name:
                    asset_url = asset["browser_download_url"]
                    break

            if asset_url is None:
                return False

            # Download the zip
            dl = requests.get(asset_url, stream=True, timeout=60)
            dl.raise_for_status()
            total = int(dl.headers.get("content-length", 0))
            buf = io.BytesIO()
            downloaded = 0
            for chunk in dl.iter_content(chunk_size=65536):
                buf.write(chunk)
                downloaded += len(chunk)
                if progress_cb and total:
                    progress_cb(min(downloaded / total, 1.0))

            # Extract the binary
            buf.seek(0)
            with zipfile.ZipFile(buf) as zf:
                for member in zf.namelist():
                    if member.endswith(_bin_name()):
                        data = zf.read(member)
                        self.bin_path.write_bytes(data)
                        if platform.system() != "Windows":
                            self.bin_path.chmod(0o755)
                        return True
            return False
        except Exception as exc:
            print(f"[SingBoxManager] download error: {exc}")
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def set_callbacks(
        self,
        on_status_change: Optional[Callable[[str], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._on_status_change = on_status_change
        self._on_log = on_log

    def write_config(self, config: dict) -> None:
        """Write a sing-box JSON config to the data directory."""
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

    def start(self) -> bool:
        """Start the sing-box process. Returns True on success."""
        if self.is_running:
            return True
        if not self.is_installed():
            return False
        if not self.config_path.exists():
            return False

        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            self._process = subprocess.Popen(
                [str(self.bin_path), "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=creation_flags,
            )
            self._stop_event.clear()
            self._started_ok = False
            self._monitor_thread = threading.Thread(target=self._monitor, daemon=True)
            self._monitor_thread.start()
            # Don't set 'connected' immediately — _monitor will detect it from logs
            return True
        except Exception as exc:
            self._emit_log(f"Failed to start sing-box: {exc}")
            self._emit_status("error")
            return False

    def stop(self) -> None:
        """Stop the sing-box process."""
        self._stop_event.set()
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            self._process = None
        self._emit_status("disconnected")

    def check_config(self) -> tuple[bool, str]:
        """Validate the current config with sing-box. Returns (ok, message)."""
        if not self.is_installed() or not self.config_path.exists():
            return False, "sing-box not installed or config missing"
        try:
            result = subprocess.run(
                [str(self.bin_path), "check", "-c", str(self.config_path)],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            if result.returncode == 0:
                return True, "Config OK"
            # Ignore warnings — only treat actual errors as failures
            stderr = result.stderr.strip() or result.stdout.strip()
            # Filter out WARN lines, keep only ERROR/FATAL
            error_lines = [
                ln for ln in stderr.splitlines()
                if "WARN" not in ln and "warn" not in ln.lower().split("]")[0]
            ]
            if not error_lines:
                return True, "Config OK (with warnings)"
            return False, "\n".join(error_lines)
        except Exception as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _monitor(self) -> None:
        """Read stdout from sing-box and emit logs."""
        proc = self._process
        if proc is None or proc.stdout is None:
            return

        # Give the process a moment, then check if it's still alive
        time.sleep(0.3)
        if proc.poll() is not None:
            # Process exited immediately — likely a permissions or config error
            remaining = ""
            try:
                remaining = proc.stdout.read()
            except Exception:
                pass
            if remaining:
                for ln in remaining.strip().splitlines():
                    self._emit_log(ln)
            self._emit_log(f"sing-box exited with code {proc.returncode}")
            self._emit_status("error")
            return

        # Process is still running — mark connected
        self._started_ok = True
        self._emit_status("connected")

        try:
            for line in proc.stdout:
                if self._stop_event.is_set():
                    break
                stripped = line.rstrip("\n")
                self._emit_log(stripped)
                # Detect fatal errors in output
                if "FATAL" in stripped or "fatal" in stripped:
                    self._emit_status("error")
        except Exception:
            pass

        # Process ended unexpectedly
        if not self._stop_event.is_set():
            rc = proc.poll()
            if rc is not None and rc != 0:
                self._emit_log(f"sing-box exited with code {rc}")
                self._emit_status("error")
            else:
                self._emit_status("disconnected")

    def _emit_status(self, status: str) -> None:
        if self._on_status_change:
            try:
                self._on_status_change(status)
            except Exception:
                pass

    def _emit_log(self, line: str) -> None:
        if self._on_log:
            try:
                self._on_log(line)
            except Exception:
                pass
