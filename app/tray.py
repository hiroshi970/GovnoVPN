"""
System tray icon for GovnoVPN.

Uses pystray + Pillow to create a tray icon that lives alongside the main window.
"""

import threading
from typing import Callable, Optional

try:
    from PIL import Image, ImageDraw, ImageFont
    import pystray
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


def _make_icon(connected: bool = False) -> "Image.Image":
    """Generate a compact poop emoji icon programmatically."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    body_color = (34, 197, 94) if connected else (139, 90, 43)
    dark_color = (16, 150, 72) if connected else (101, 67, 33)

    # Wide base
    draw.ellipse([6, 34, 58, 60], fill=body_color, outline=dark_color)
    # Middle body (wide)
    draw.ellipse([10, 22, 54, 48], fill=body_color, outline=dark_color)
    # Top swirl
    draw.ellipse([22, 12, 42, 30], fill=body_color, outline=dark_color)
    # Tip
    draw.ellipse([28, 6, 38, 18], fill=body_color, outline=dark_color)

    # Eyes
    draw.ellipse([22, 30, 30, 38], fill="white")
    draw.ellipse([34, 30, 42, 38], fill="white")
    draw.ellipse([24, 32, 28, 36], fill="black")
    draw.ellipse([36, 32, 40, 36], fill="black")

    # Smile
    draw.arc([24, 38, 40, 48], start=0, end=180, fill="black", width=2)

    return img


class TrayManager:
    """Manages the system tray icon + context menu."""

    def __init__(
        self,
        on_show: Optional[Callable] = None,
        on_quit: Optional[Callable] = None,
        on_connect: Optional[Callable] = None,
        on_disconnect: Optional[Callable] = None,
    ):
        self._on_show = on_show
        self._on_quit = on_quit
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._icon: Optional["pystray.Icon"] = None
        self._connected = False

    @property
    def available(self) -> bool:
        return TRAY_AVAILABLE

    def start(self) -> None:
        if not TRAY_AVAILABLE:
            return

        menu = pystray.Menu(
            pystray.MenuItem("Показать", self._show, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Подключиться", self._connect, visible=lambda _: not self._connected),
            pystray.MenuItem("Отключиться", self._disconnect, visible=lambda _: self._connected),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", self._quit),
        )

        self._icon = pystray.Icon(
            name="GovnoVPN",
            icon=_make_icon(False),
            title="GovnoVPN — Отключено",
            menu=menu,
        )

        thread = threading.Thread(target=self._icon.run, daemon=True)
        thread.start()

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                pass

    def set_connected(self, connected: bool) -> None:
        self._connected = connected
        if self._icon is not None:
            self._icon.icon = _make_icon(connected)
            self._icon.title = f"GovnoVPN — {'Подключено' if connected else 'Отключено'}"
            self._icon.update_menu()

    # Callbacks
    def _show(self, icon=None, item=None) -> None:
        if self._on_show:
            self._on_show()

    def _quit(self, icon=None, item=None) -> None:
        if self._on_quit:
            self._on_quit()

    def _connect(self, icon=None, item=None) -> None:
        if self._on_connect:
            self._on_connect()

    def _disconnect(self, icon=None, item=None) -> None:
        if self._on_disconnect:
            self._on_disconnect()
