#!/usr/bin/env python3
"""
GovnoVPN — VLESS-клиент на основе sing-box.

Entry point.
"""

import sys
import os
import platform

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _ensure_admin() -> None:
    """On Windows, re-launch as Administrator if not already elevated.
    TUN mode requires admin privileges."""
    if platform.system() != "Windows":
        return
    import ctypes
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    # Re-launch elevated
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1,
    )
    sys.exit(0)


from app.gui import GovnoVPNApp
from app.tray import TrayManager


def main() -> None:
    app = GovnoVPNApp()

    # ---- System tray integration ----------------------------------------
    tray = TrayManager(
        on_show=lambda: app.after(0, _show_window, app),
        on_quit=lambda: app.after(0, app.on_closing),
        on_connect=lambda: app.after(0, app._connect),
        on_disconnect=lambda: app.after(0, app._disconnect),
    )

    # Wire status changes to tray
    original_set_status = app._set_status

    def _patched_set_status(status: str) -> None:
        original_set_status(status)
        tray.set_connected(status == "connected")

    app._set_status = _patched_set_status

    # Minimize to tray instead of quitting
    def _on_close() -> None:
        if tray.available:
            app.withdraw()  # hide to tray
        else:
            app.on_closing()

    app.protocol("WM_DELETE_WINDOW", _on_close)

    if tray.available:
        tray.start()

    app.mainloop()
    tray.stop()


def _show_window(app: GovnoVPNApp) -> None:
    app.deiconify()
    app.lift()
    app.focus_force()


if __name__ == "__main__":
    _ensure_admin()
    main()
