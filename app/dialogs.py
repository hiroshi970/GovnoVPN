"""
Dialog windows for GovnoVPN — add/edit VLESS profiles, settings, about, etc.
"""

import threading
import webbrowser
import customtkinter as ctk
import subprocess
import platform
from typing import Optional, Callable, TYPE_CHECKING

import qrcode
from PIL import Image, ImageDraw

from app.profiles import VlessProfile, parse_vless_url, profile_to_vless_url, DomainWhitelist
from app.domain_parser import discover_domains_async

if TYPE_CHECKING:
    from app.auth import AuthManager
    from app.settings import AppSettings


# ======================================================================
# Add / Edit Profile Dialog
# ======================================================================

class ProfileDialog(ctk.CTkToplevel):
    """Modal dialog for adding or editing a VLESS profile."""

    WIDTH = 560
    HEIGHT = 680

    def __init__(
        self,
        master,
        profile: Optional[VlessProfile] = None,
        on_save: Optional[Callable[[VlessProfile], None]] = None,
    ):
        super().__init__(master)
        self._profile = profile or VlessProfile()
        self._on_save = on_save
        self._is_edit = profile is not None

        self.title("Редактировать профиль" if self._is_edit else "Добавить профиль")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._build_ui()
        if self._is_edit:
            self._populate()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        pad = {"padx": 16, "pady": (4, 0)}

        # === Quick import bar ===========================================
        import_frame = ctk.CTkFrame(self, fg_color="transparent")
        import_frame.pack(fill="x", padx=16, pady=(12, 0))
        ctk.CTkLabel(import_frame, text="Вставьте VLESS ссылку:", font=ctk.CTkFont(size=12)).pack(anchor="w")
        link_row = ctk.CTkFrame(import_frame, fg_color="transparent")
        link_row.pack(fill="x", pady=(4, 0))
        self._link_entry = ctk.CTkEntry(link_row, placeholder_text="vless://...", height=36)
        self._link_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(link_row, text="Импорт", width=90, height=36, command=self._import_link).pack(side="right")

        sep = ctk.CTkFrame(self, height=2, fg_color=("gray80", "gray30"))
        sep.pack(fill="x", padx=16, pady=12)

        # === Scrollable form ============================================
        form = ctk.CTkScrollableFrame(self, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Helper to create labelled entry
        def entry(parent, label: str, placeholder: str = "", **kwargs) -> ctk.CTkEntry:
            ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
            e = ctk.CTkEntry(parent, placeholder_text=placeholder, height=34, **kwargs)
            e.pack(fill="x", **pad)
            return e

        self._name = entry(form, "Название", "My Server")
        self._address = entry(form, "Адрес сервера", "example.com")
        self._port = entry(form, "Порт", "443")
        self._uuid = entry(form, "UUID", "xxxxxxxx-xxxx-...")

        # Flow
        ctk.CTkLabel(form, text="Flow", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._flow = ctk.CTkComboBox(
            form,
            values=["", "xtls-rprx-vision"],
            height=34,
        )
        self._flow.pack(fill="x", **pad)
        self._flow.set("")

        # Network / Transport
        ctk.CTkLabel(form, text="Транспорт", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._network = ctk.CTkSegmentedButton(
            form,
            values=["tcp", "ws", "grpc", "http"],
            command=self._on_network_change,
        )
        self._network.pack(fill="x", **pad)
        self._network.set("tcp")

        # Transport-specific fields (hidden by default)
        self._ws_frame = ctk.CTkFrame(form, fg_color="transparent")
        self._ws_path = entry(self._ws_frame, "WS Path", "/")
        self._ws_host = entry(self._ws_frame, "WS Host", "")

        self._grpc_frame = ctk.CTkFrame(form, fg_color="transparent")
        self._grpc_sn = entry(self._grpc_frame, "gRPC Service Name", "")

        self._http_frame = ctk.CTkFrame(form, fg_color="transparent")
        self._http_path = entry(self._http_frame, "HTTP Path", "/")
        self._http_host = entry(self._http_frame, "HTTP Host", "")

        # Security
        ctk.CTkLabel(form, text="Безопасность", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._security = ctk.CTkSegmentedButton(
            form,
            values=["tls", "reality", "none"],
            command=self._on_security_change,
        )
        self._security.pack(fill="x", **pad)
        self._security.set("tls")

        # TLS / Reality fields
        self._tls_frame = ctk.CTkFrame(form, fg_color="transparent")
        self._sni = entry(self._tls_frame, "SNI", "example.com")
        self._fingerprint = entry(self._tls_frame, "Fingerprint", "chrome")
        self._alpn = entry(self._tls_frame, "ALPN (через запятую)", "h2,http/1.1")
        self._allow_insecure = ctk.CTkCheckBox(self._tls_frame, text="Разрешить небезопасные сертификаты")
        self._allow_insecure.pack(anchor="w", **pad)
        self._tls_frame.pack(fill="x")

        self._reality_frame = ctk.CTkFrame(form, fg_color="transparent")
        self._pbk = entry(self._reality_frame, "Public Key", "")
        self._sid = entry(self._reality_frame, "Short ID", "")

        self._on_security_change("tls")
        self._on_network_change("tcp")

        # === Buttons ====================================================
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 16))
        ctk.CTkButton(btn_frame, text="Отмена", width=120, fg_color=("gray65", "gray40"), hover_color=("gray55", "gray50"),
                       command=self.destroy).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_frame, text="Сохранить", width=120, command=self._save).pack(side="right")

    # ------------------------------------------------------------------
    # Dynamic visibility
    # ------------------------------------------------------------------

    def _on_network_change(self, value: str) -> None:
        for f in (self._ws_frame, self._grpc_frame, self._http_frame):
            f.pack_forget()
        if value == "ws":
            self._ws_frame.pack(fill="x")
        elif value == "grpc":
            self._grpc_frame.pack(fill="x")
        elif value == "http":
            self._http_frame.pack(fill="x")

    def _on_security_change(self, value: str) -> None:
        self._tls_frame.pack_forget()
        self._reality_frame.pack_forget()
        if value in ("tls", "reality"):
            self._tls_frame.pack(fill="x")
        if value == "reality":
            self._reality_frame.pack(fill="x")

    # ------------------------------------------------------------------
    # Import from link
    # ------------------------------------------------------------------

    def _import_link(self) -> None:
        url = self._link_entry.get().strip()
        if not url:
            return
        profile = parse_vless_url(url)
        if profile is None:
            return
        # Keep original id if editing
        if self._is_edit:
            profile.id = self._profile.id
        self._profile = profile
        self._populate()

    # ------------------------------------------------------------------
    # Populate fields from profile
    # ------------------------------------------------------------------

    def _populate(self) -> None:
        p = self._profile

        def _set(entry: ctk.CTkEntry, val: str) -> None:
            entry.delete(0, "end")
            entry.insert(0, val)

        _set(self._name, p.name)
        _set(self._address, p.address)
        _set(self._port, str(p.port))
        _set(self._uuid, p.uuid)
        self._flow.set(p.flow)
        self._network.set(p.network)
        self._on_network_change(p.network)
        _set(self._ws_path, p.path)
        _set(self._ws_host, p.host)
        _set(self._grpc_sn, p.service_name)
        _set(self._http_path, p.path)
        _set(self._http_host, p.host)
        self._security.set(p.security)
        self._on_security_change(p.security)
        _set(self._sni, p.sni)
        _set(self._fingerprint, p.fingerprint)
        _set(self._alpn, p.alpn)
        if p.allow_insecure:
            self._allow_insecure.select()
        else:
            self._allow_insecure.deselect()
        _set(self._pbk, p.public_key)
        _set(self._sid, p.short_id)

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def _save(self) -> None:
        p = self._profile
        p.name = self._name.get().strip()
        p.address = self._address.get().strip()
        try:
            p.port = int(self._port.get().strip())
        except ValueError:
            p.port = 443
        p.uuid = self._uuid.get().strip()
        p.flow = self._flow.get().strip()
        p.network = self._network.get()
        p.security = self._security.get()
        p.sni = self._sni.get().strip()
        p.fingerprint = self._fingerprint.get().strip()
        p.alpn = self._alpn.get().strip()
        p.allow_insecure = self._allow_insecure.get() == 1

        if p.network == "ws":
            p.path = self._ws_path.get().strip()
            p.host = self._ws_host.get().strip()
        elif p.network == "grpc":
            p.service_name = self._grpc_sn.get().strip()
        elif p.network == "http":
            p.path = self._http_path.get().strip()
            p.host = self._http_host.get().strip()

        if p.security == "reality":
            p.public_key = self._pbk.get().strip()
            p.short_id = self._sid.get().strip()

        if not p.address or not p.uuid:
            return  # basic validation

        if self._on_save:
            self._on_save(p)
        self.destroy()


# ======================================================================
# About Dialog
# ======================================================================

class AboutDialog(ctk.CTkToplevel):
    _TG_URL = "https://t.me/Tachikoma_Unit"

    def __init__(self, master):
        super().__init__(master)
        self.title("О программе")
        self.geometry("380x480")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        ctk.CTkLabel(self, text="GovnoVPN", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(24, 4))
        ctk.CTkLabel(self, text="v1.0.0", font=ctk.CTkFont(size=13)).pack()

        ctk.CTkLabel(
            self,
            text="С говном и любовью \u2764",
            font=ctk.CTkFont(size=15, weight="bold"),
            justify="center",
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            self,
            text="@Tachikoma_Unit",
            font=ctk.CTkFont(size=14),
            text_color=("#0088cc", "#44aaee"),
            cursor="hand2",
        ).pack(pady=(0, 8))
        # Make username clickable
        for child in self.winfo_children():
            pass
        self.winfo_children()[-1].bind("<Button-1>", lambda e: webbrowser.open(self._TG_URL))

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(self._TG_URL)
        qr.make(fit=True)
        qr_pil = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
        self._qr_img = ctk.CTkImage(light_image=qr_pil, dark_image=qr_pil, size=(180, 180))

        qr_label = ctk.CTkLabel(self, text="", image=self._qr_img, cursor="hand2")
        qr_label.pack(pady=(0, 8))
        qr_label.bind("<Button-1>", lambda e: webbrowser.open(self._TG_URL))

        ctk.CTkLabel(
            self,
            text="Делалось для себя, предоставляется как есть",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
            justify="center",
        ).pack(pady=(0, 8))

        ctk.CTkButton(self, text="Закрыть", width=100, command=self.destroy).pack(pady=(4, 16))


# ======================================================================
# Settings Dialog
# ======================================================================

class SettingsDialog(ctk.CTkToplevel):
    """Application settings — appearance, streamer mode, sing-box path, etc."""

    def __init__(
        self,
        master,
        settings: Optional["AppSettings"] = None,
        on_theme_change: Optional[Callable[[str], None]] = None,
        on_streamer_toggle: Optional[Callable[[bool], None]] = None,
        on_reopen: Optional[Callable[[], None]] = None,
    ):
        super().__init__(master)
        self._settings = settings
        self._on_theme_change = on_theme_change
        self._on_streamer_toggle = on_streamer_toggle
        self._on_reopen = on_reopen
        self.title("Настройки")
        self.geometry("420x460")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        pad = {"padx": 20, "pady": (10, 0)}

        ctk.CTkLabel(self, text="Настройки", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 10))

        # Theme
        ctk.CTkLabel(self, text="Тема оформления", font=ctk.CTkFont(size=13)).pack(anchor="w", **pad)
        self._theme = ctk.CTkSegmentedButton(
            self,
            values=["System", "Dark", "Light"],
            command=self._change_theme,
        )
        self._theme.pack(fill="x", padx=20, pady=(6, 0))
        current = ctk.get_appearance_mode()
        self._theme.set(current if current in ("Dark", "Light") else "System")

        # Color accent
        ctk.CTkLabel(self, text="Цветовая схема", font=ctk.CTkFont(size=13)).pack(anchor="w", **pad)
        self._color = ctk.CTkComboBox(
            self,
            values=["blue", "green", "dark-blue"],
            height=32,
            command=self._change_color,
        )
        self._color.pack(fill="x", padx=20, pady=(6, 0))
        saved_color = self._settings.get("color_theme", "blue") if self._settings else "blue"
        self._color.set(saved_color)
        ctk.CTkLabel(
            self, text="Применится после перезапуска",
            font=ctk.CTkFont(size=10),
            text_color=("gray50", "gray60"),
        ).pack(anchor="w", padx=20, pady=(2, 0))

        # ---- Streamer mode ------------------------------------------------
        sep = ctk.CTkFrame(self, height=2, fg_color=("gray80", "gray30"))
        sep.pack(fill="x", padx=20, pady=(16, 8))

        streamer_frame = ctk.CTkFrame(self, fg_color="transparent")
        streamer_frame.pack(fill="x", padx=20, pady=(4, 0))

        ctk.CTkLabel(
            streamer_frame, text="🎥  Режим стримера",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(side="left")

        self._streamer_switch = ctk.CTkSwitch(
            streamer_frame, text="",
            command=self._toggle_streamer,
            onvalue=True, offvalue=False,
        )
        self._streamer_switch.pack(side="right")
        if self._settings and self._settings.streamer_mode:
            self._streamer_switch.select()

        ctk.CTkLabel(
            self,
            text="Скрывает IP-адреса, UUID, серверные данные\nи другую чувствительную информацию в интерфейсе.",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=20, pady=(4, 0))

        ctk.CTkButton(self, text="Закрыть", width=120, command=self.destroy).pack(pady=(28, 20))

    def _change_theme(self, value: str) -> None:
        if self._settings:
            self._settings.set("theme", value.lower())
        if self._on_theme_change:
            self._on_theme_change(value)
        # Destroy this dialog, apply theme, then reopen via main window
        self.grab_release()
        self.destroy()
        ctk.set_appearance_mode(value.lower())
        if self._on_reopen:
            self._on_reopen()

    def _change_color(self, value: str) -> None:
        # Color theme only takes effect on next launch
        if self._settings:
            self._settings.set("color_theme", value)

    def _toggle_streamer(self) -> None:
        enabled = bool(self._streamer_switch.get())
        if self._settings:
            self._settings.streamer_mode = enabled
        if self._on_streamer_toggle:
            self._on_streamer_toggle(enabled)


# ======================================================================
# Log Viewer Dialog
# ======================================================================

class LogDialog(ctk.CTkToplevel):
    """Floating log viewer."""

    def __init__(self, master):
        super().__init__(master)
        self.title("Журнал")
        self.geometry("700x420")
        self.transient(master)

        self._textbox = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=12), state="disabled")
        self._textbox.pack(fill="both", expand=True, padx=8, pady=8)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(btn_frame, text="Очистить", width=100, command=self._clear).pack(side="left")
        ctk.CTkButton(btn_frame, text="Закрыть", width=100, command=self.destroy).pack(side="right")

    def append(self, line: str) -> None:
        self._textbox.configure(state="normal")
        self._textbox.insert("end", line + "\n")
        self._textbox.see("end")
        self._textbox.configure(state="disabled")

    def _clear(self) -> None:
        self._textbox.configure(state="normal")
        self._textbox.delete("1.0", "end")
        self._textbox.configure(state="disabled")


# ======================================================================
# Domain Whitelist Dialog
# ======================================================================

class WhitelistDialog(ctk.CTkToplevel):
    """Dialog for managing domain + process whitelist (split-tunneling)."""

    WIDTH = 600
    HEIGHT = 640

    def __init__(
        self,
        master,
        whitelist: DomainWhitelist,
        on_change: Optional[Callable[[], None]] = None,
        is_vpn_connected: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(master)
        self._wl = whitelist
        self._on_change = on_change
        self._is_vpn_connected = is_vpn_connected

        self.title("Белый список")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(True, True)
        self.minsize(480, 450)
        self.transient(master)
        self.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        # ---- Header with toggle -------------------------------------------
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 4))

        ctk.CTkLabel(
            header,
            text="Белый список",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(side="left")

        self._enabled_switch = ctk.CTkSwitch(
            header,
            text="Вкл.",
            command=self._toggle_enabled,
            onvalue=True,
            offvalue=False,
        )
        self._enabled_switch.pack(side="right")
        if self._wl.enabled:
            self._enabled_switch.select()
        else:
            self._enabled_switch.deselect()

        ctk.CTkLabel(
            self,
            text="Указанные домены и процессы пойдут через VLESS. Остальной трафик — напрямую.",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=16, pady=(4, 4))

        # ---- Tabview: Домены | Процессы -----------------------------------
        self._tabs = ctk.CTkTabview(self)
        self._tabs.pack(fill="both", expand=True, padx=12, pady=(4, 0))

        self._build_domains_tab(self._tabs.add("Домены"))
        self._build_processes_tab(self._tabs.add("Процессы"))

        # ---- Bottom buttons ------------------------------------------------
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 12))

        self._count_label = ctk.CTkLabel(
            btn_frame, text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        )
        self._count_label.pack(side="left")

        ctk.CTkButton(
            btn_frame, text="Закрыть", width=100,
            command=self.destroy,
        ).pack(side="right")

        self._update_counts()

    # ==================================================================
    # Domains tab
    # ==================================================================

    def _build_domains_tab(self, parent) -> None:
        # Add bar
        add_row = ctk.CTkFrame(parent, fg_color="transparent")
        add_row.pack(fill="x", pady=(4, 4))

        self._domain_entry = ctk.CTkEntry(
            add_row, placeholder_text="например: youtube.com", height=36,
        )
        self._domain_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._domain_entry.bind("<Return>", lambda e: self._add_domain())

        ctk.CTkButton(
            add_row, text="Добавить", width=100, height=36,
            command=self._add_domain,
        ).pack(side="right", padx=(0, 4))

        ctk.CTkButton(
            add_row, text="🔍 Парсить", width=100, height=36,
            fg_color=("#2a7a2a", "#1a5c1a"),
            hover_color=("#1e6e1e", "#227722"),
            command=self._parse_domain,
        ).pack(side="right")

        # Presets
        preset_frame = ctk.CTkFrame(parent, fg_color="transparent")
        preset_frame.pack(fill="x", pady=(0, 4))

        ctk.CTkLabel(
            preset_frame, text="Быстро:",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        ).pack(side="left", padx=(0, 4))

        presets = {
            "YouTube": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"],
            "Google": ["google.com", "googleapis.com", "gstatic.com"],
            "Instagram": ["instagram.com", "cdninstagram.com", "fbcdn.net"],
            "Twitter/X": ["twitter.com", "x.com", "twimg.com", "t.co"],
            "Discord": ["discord.com", "discord.gg", "discordapp.com"],
            "Telegram": ["telegram.org", "t.me", "telegram.me"],
        }
        for name, domains in presets.items():
            ctk.CTkButton(
                preset_frame, text=name, width=0, height=24,
                font=ctk.CTkFont(size=10),
                fg_color=("gray80", "gray30"),
                hover_color=("gray70", "gray40"),
                text_color=("gray20", "gray90"),
                command=lambda ds=domains: self._add_preset_domains(ds),
            ).pack(side="left", padx=2)

        ctk.CTkButton(
            preset_frame, text="Очистить", width=0, height=24,
            font=ctk.CTkFont(size=10),
            fg_color="transparent", hover_color=("gray85", "gray25"),
            text_color=("#cc0000", "#ff6666"),
            command=self._clear_domains,
        ).pack(side="right")

        # List
        self._domain_list = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self._domain_list.pack(fill="both", expand=True, pady=(0, 4))
        self._domain_widgets: list = []
        self._refresh_domain_list()

    # ==================================================================
    # Processes tab
    # ==================================================================

    def _build_processes_tab(self, parent) -> None:
        # Description
        ctk.CTkLabel(
            parent,
            text="Весь трафик выбранных процессов пойдёт через VLESS.",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        ).pack(anchor="w", pady=(4, 4))

        # Add bar
        add_row = ctk.CTkFrame(parent, fg_color="transparent")
        add_row.pack(fill="x", pady=(0, 4))

        self._proc_entry = ctk.CTkEntry(
            add_row, placeholder_text="например: chrome.exe", height=36,
        )
        self._proc_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._proc_entry.bind("<Return>", lambda e: self._add_process_manual())

        ctk.CTkButton(
            add_row, text="Добавить", width=100, height=36,
            command=self._add_process_manual,
        ).pack(side="right")

        # Preset process buttons
        preset_frame = ctk.CTkFrame(parent, fg_color="transparent")
        preset_frame.pack(fill="x", pady=(0, 4))

        ctk.CTkLabel(
            preset_frame, text="Быстро:",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        ).pack(side="left", padx=(0, 4))

        proc_presets = {
            "Chrome": "chrome.exe",
            "Firefox": "firefox.exe",
            "Edge": "msedge.exe",
            "Opera": "opera.exe",
            "Telegram": "Telegram.exe",
            "Discord": "Discord.exe",
        }
        for name, proc in proc_presets.items():
            ctk.CTkButton(
                preset_frame, text=name, width=0, height=24,
                font=ctk.CTkFont(size=10),
                fg_color=("gray80", "gray30"),
                hover_color=("gray70", "gray40"),
                text_color=("gray20", "gray90"),
                command=lambda p=proc: self._add_process(p),
            ).pack(side="left", padx=2)

        ctk.CTkButton(
            preset_frame, text="Очистить", width=0, height=24,
            font=ctk.CTkFont(size=10),
            fg_color="transparent", hover_color=("gray85", "gray25"),
            text_color=("#cc0000", "#ff6666"),
            command=self._clear_processes,
        ).pack(side="right")

        # Running processes picker
        pick_frame = ctk.CTkFrame(parent, fg_color="transparent")
        pick_frame.pack(fill="x", pady=(0, 4))

        ctk.CTkButton(
            pick_frame, text="📋 Выбрать из запущенных", width=200, height=30,
            font=ctk.CTkFont(size=11),
            command=self._pick_running_process,
        ).pack(side="left")

        # Process list
        self._proc_list = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        self._proc_list.pack(fill="both", expand=True, pady=(0, 4))
        self._proc_widgets: list = []
        self._refresh_proc_list()

    # ==================================================================
    # Domain actions
    # ==================================================================

    def _add_domain(self) -> None:
        raw = self._domain_entry.get().strip()
        if not raw:
            return
        parts = [d.strip().lower() for d in raw.replace(",", "\\n").splitlines() if d.strip()]
        for d in parts:
            d = d.removeprefix("http://").removeprefix("https://").split("/")[0]
            self._wl.add(d)
        self._domain_entry.delete(0, "end")
        self._refresh_domain_list()
        self._notify()

    def _parse_domain(self) -> None:
        """Open the Domain Discovery dialog for the entered domain."""
        raw = self._domain_entry.get().strip()
        if not raw:
            return
        domain = raw.removeprefix("http://").removeprefix("https://").split("/")[0]
        DomainDiscoveryDialog(
            self,
            domain=domain,
            on_add=self._on_discovered_domains_add,
            is_vpn_connected=self._is_vpn_connected,
        )

    def _on_discovered_domains_add(self, domains: list[str]) -> None:
        """Callback when user confirms discovered domains."""
        for d in domains:
            self._wl.add(d)
        self._domain_entry.delete(0, "end")
        self._refresh_domain_list()
        self._notify()

    def _add_preset_domains(self, domains: list[str]) -> None:
        for d in domains:
            self._wl.add(d)
        self._refresh_domain_list()
        self._notify()

    def _remove_domain(self, domain: str) -> None:
        self._wl.remove(domain)
        self._refresh_domain_list()
        self._notify()

    def _clear_domains(self) -> None:
        self._wl.domains.clear()
        self._wl.save()
        self._refresh_domain_list()
        self._notify()

    def _refresh_domain_list(self) -> None:
        for w in self._domain_widgets:
            w.destroy()
        self._domain_widgets.clear()

        for domain in sorted(self._wl.domains):
            row = ctk.CTkFrame(self._domain_list, corner_radius=8, height=34)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            ctk.CTkLabel(
                row, text=f"🌐  {domain}",
                font=ctk.CTkFont(size=12), anchor="w",
            ).pack(side="left", padx=(10, 0), fill="x", expand=True)

            ctk.CTkButton(
                row, text="✕", width=30, height=26,
                font=ctk.CTkFont(size=12),
                fg_color="transparent",
                hover_color=("#ffcccc", "#5c2020"),
                text_color=("#cc0000", "#ff6666"),
                command=lambda d=domain: self._remove_domain(d),
            ).pack(side="right", padx=4)

            self._domain_widgets.append(row)

        self._update_counts()

    # ==================================================================
    # Process actions
    # ==================================================================

    def _add_process_manual(self) -> None:
        raw = self._proc_entry.get().strip()
        if not raw:
            return
        parts = [p.strip() for p in raw.replace(",", "\\n").splitlines() if p.strip()]
        for p in parts:
            self._wl.add_process(p)
        self._proc_entry.delete(0, "end")
        self._refresh_proc_list()
        self._notify()

    def _add_process(self, name: str) -> None:
        self._wl.add_process(name)
        self._refresh_proc_list()
        self._notify()

    def _remove_process(self, name: str) -> None:
        self._wl.remove_process(name)
        self._refresh_proc_list()
        self._notify()

    def _clear_processes(self) -> None:
        self._wl.processes.clear()
        self._wl.save()
        self._refresh_proc_list()
        self._notify()

    def _pick_running_process(self) -> None:
        """Open a sub-dialog listing currently running processes to pick from."""
        ProcessPickerDialog(self, on_select=self._on_process_picked)

    def _on_process_picked(self, names: list[str]) -> None:
        for n in names:
            self._wl.add_process(n)
        self._refresh_proc_list()
        self._notify()

    def _refresh_proc_list(self) -> None:
        for w in self._proc_widgets:
            w.destroy()
        self._proc_widgets.clear()

        for proc in sorted(self._wl.processes):
            row = ctk.CTkFrame(self._proc_list, corner_radius=8, height=34)
            row.pack(fill="x", pady=2)
            row.pack_propagate(False)

            ctk.CTkLabel(
                row, text=f"⚙  {proc}",
                font=ctk.CTkFont(size=12), anchor="w",
            ).pack(side="left", padx=(10, 0), fill="x", expand=True)

            ctk.CTkButton(
                row, text="✕", width=30, height=26,
                font=ctk.CTkFont(size=12),
                fg_color="transparent",
                hover_color=("#ffcccc", "#5c2020"),
                text_color=("#cc0000", "#ff6666"),
                command=lambda n=proc: self._remove_process(n),
            ).pack(side="right", padx=4)

            self._proc_widgets.append(row)

        self._update_counts()

    # ==================================================================
    # Common
    # ==================================================================

    def _toggle_enabled(self) -> None:
        self._wl.set_enabled(bool(self._enabled_switch.get()))
        self._notify()

    def _notify(self) -> None:
        self._update_counts()
        if self._on_change:
            self._on_change()

    def _update_counts(self) -> None:
        try:
            nd = len(self._wl.domains)
            np = len(self._wl.processes)
            parts = []
            if nd:
                parts.append(f"{nd} домен(ов)")
            if np:
                parts.append(f"{np} процесс(ов)")
            self._count_label.configure(text=" • ".join(parts) if parts else "Пусто")
        except Exception:
            pass


# ======================================================================
# Running Process Picker Dialog
# ======================================================================

class ProcessPickerDialog(ctk.CTkToplevel):
    """Lists running processes for the user to select."""

    WIDTH = 460
    HEIGHT = 520

    def __init__(self, master, on_select: Optional[Callable[[list], None]] = None):
        super().__init__(master)
        self._on_select = on_select
        self._selected: set[str] = set()

        self.title("Выбрать процессы")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(True, True)
        self.minsize(360, 380)
        self.transient(master)
        self.grab_set()

        self._build_ui()
        self._load_processes()

    def _build_ui(self) -> None:
        # Search
        search_row = ctk.CTkFrame(self, fg_color="transparent")
        search_row.pack(fill="x", padx=12, pady=(12, 4))

        self._search_entry = ctk.CTkEntry(
            search_row, placeholder_text="Поиск процесса…", height=34,
        )
        self._search_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._search_entry.bind("<KeyRelease>", lambda e: self._filter_list())

        ctk.CTkButton(
            search_row, text="🔄", width=34, height=34,
            command=self._load_processes,
        ).pack(side="right")

        # Process list
        self._list_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._list_frame.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self._list_widgets: list = []

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 12))

        self._sel_label = ctk.CTkLabel(
            btn_frame, text="Выбрано: 0",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        )
        self._sel_label.pack(side="left")

        ctk.CTkButton(
            btn_frame, text="Отмена", width=90,
            fg_color=("gray65", "gray40"), hover_color=("gray55", "gray50"),
            command=self.destroy,
        ).pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            btn_frame, text="Добавить", width=90,
            command=self._confirm,
        ).pack(side="right")

    def _load_processes(self) -> None:
        """Get a sorted unique list of running process names."""
        self._all_procs: list[str] = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                seen = set()
                for line in result.stdout.strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        name = parts[0].strip().strip('"')
                        if name and name not in seen:
                            seen.add(name)
                            self._all_procs.append(name)
            else:
                result = subprocess.run(
                    ["ps", "-eo", "comm", "--no-headers"],
                    capture_output=True, text=True, timeout=10,
                )
                seen = set()
                for line in result.stdout.strip().splitlines():
                    name = line.strip().split("/")[-1]
                    if name and name not in seen:
                        seen.add(name)
                        self._all_procs.append(name)
        except Exception:
            pass

        self._all_procs.sort(key=str.lower)
        self._filter_list()

    def _filter_list(self) -> None:
        query = self._search_entry.get().strip().lower()

        for w in self._list_widgets:
            w.destroy()
        self._list_widgets.clear()

        for proc in self._all_procs:
            if query and query not in proc.lower():
                continue
            row = ctk.CTkFrame(self._list_frame, corner_radius=6, height=32)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            var = ctk.BooleanVar(value=proc in self._selected)
            cb = ctk.CTkCheckBox(
                row, text=proc,
                font=ctk.CTkFont(size=11),
                variable=var,
                height=24, checkbox_width=20, checkbox_height=20,
                command=lambda n=proc, v=var: self._toggle_proc(n, v),
            )
            cb.pack(side="left", padx=8, pady=2)
            self._list_widgets.append(row)

    def _toggle_proc(self, name: str, var: ctk.BooleanVar) -> None:
        if var.get():
            self._selected.add(name)
        else:
            self._selected.discard(name)
        self._sel_label.configure(text=f"Выбрано: {len(self._selected)}")

    def _confirm(self) -> None:
        if self._on_select and self._selected:
            self._on_select(sorted(self._selected))
        self.destroy()


# ======================================================================
# Domain Discovery Dialog — auto-parse related domains for a website
# ======================================================================

class DomainDiscoveryDialog(ctk.CTkToplevel):
    """Fetches a website, discovers all related domains, and lets the user
    select which ones to add to the whitelist."""

    WIDTH = 560
    HEIGHT = 540

    def __init__(
        self,
        master,
        domain: str,
        on_add: Optional[Callable[[list], None]] = None,
        is_vpn_connected: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(master)
        self._domain = domain
        self._on_add = on_add
        self._is_vpn_connected = is_vpn_connected
        self._checkboxes: dict[str, ctk.BooleanVar] = {}
        self._list_widgets: list = []

        self.title(f"Анализ домена — {domain}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(True, True)
        self.minsize(440, 380)
        self.transient(master)
        self.grab_set()

        self._build_ui()
        self._start_scan()

    def _build_ui(self) -> None:
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 4))

        ctk.CTkLabel(
            header,
            text=f"🔍  Анализ: {self._domain}",
            font=ctk.CTkFont(size=16, weight="bold"),
        ).pack(side="left")

        ctk.CTkLabel(
            self,
            text="Программа загружает сайт и определяет все домены,\n"
                 "которые он использует (CDN, API, шрифты, медиа и т.д.).",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 8))

        # --- Deep scan checkbox ---
        scan_row = ctk.CTkFrame(self, fg_color="transparent")
        scan_row.pack(fill="x", padx=16, pady=(0, 4))

        self._deep_scan_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            scan_row,
            text="Глубокий анализ (загрузить CSS/JS файлы — медленнее)",
            variable=self._deep_scan_var,
            height=24, checkbox_width=20, checkbox_height=20,
            font=ctk.CTkFont(size=11),
        ).pack(side="left")

        ctk.CTkButton(
            scan_row, text="🔄 Повторить", width=110, height=28,
            font=ctk.CTkFont(size=11),
            command=self._start_scan,
        ).pack(side="right")

        # --- Proxy status row ---
        proxy_row = ctk.CTkFrame(self, fg_color="transparent")
        proxy_row.pack(fill="x", padx=16, pady=(0, 4))

        vpn_active = self._is_vpn_connected() if self._is_vpn_connected else False
        proxy_text = "🔒 Запросы через VLESS-прокси" if vpn_active else "🌐 Прямое соединение (подключите VPN для заблокированных сайтов)"
        proxy_color = ("#1a7a1a", "#22cc22") if vpn_active else ("gray50", "gray60")

        self._proxy_label = ctk.CTkLabel(
            proxy_row, text=proxy_text,
            font=ctk.CTkFont(size=11),
            text_color=proxy_color,
        )
        self._proxy_label.pack(side="left")

        # Status / progress
        self._status_label = ctk.CTkLabel(
            self, text="⏳ Сканирование…",
            font=ctk.CTkFont(size=12),
            text_color=("gray40", "gray70"),
        )
        self._status_label.pack(anchor="w", padx=16, pady=(4, 4))

        self._progress = ctk.CTkProgressBar(self, mode="indeterminate", height=4)
        self._progress.pack(fill="x", padx=16, pady=(0, 4))
        self._progress.start()

        # Select-all row
        sel_row = ctk.CTkFrame(self, fg_color="transparent")
        sel_row.pack(fill="x", padx=16, pady=(0, 2))

        self._select_all_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            sel_row, text="Выбрать все",
            variable=self._select_all_var,
            command=self._toggle_select_all,
            height=22, checkbox_width=18, checkbox_height=18,
            font=ctk.CTkFont(size=11),
        ).pack(side="left")

        self._count_label = ctk.CTkLabel(
            sel_row, text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        )
        self._count_label.pack(side="right")

        # Domain list (scrollable)
        self._domain_list = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._domain_list.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        # Bottom buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(4, 12))

        ctk.CTkButton(
            btn_frame, text="Отмена", width=100, height=38,
            fg_color=("gray65", "gray40"), hover_color=("gray55", "gray50"),
            command=self.destroy,
        ).pack(side="right", padx=(8, 0))

        self._add_btn = ctk.CTkButton(
            btn_frame, text="Добавить выбранные", width=180, height=38,
            state="disabled",
            command=self._confirm,
        )
        self._add_btn.pack(side="right")

    def _start_scan(self) -> None:
        """Begin (or restart) domain discovery in a background thread."""
        self._status_label.configure(
            text="⏳ Сканирование…",
            text_color=("gray40", "gray70"),
        )
        self._progress.pack(fill="x", padx=16, pady=(0, 4))
        self._progress.start()
        self._add_btn.configure(state="disabled")

        # Clear old results
        for w in self._list_widgets:
            w.destroy()
        self._list_widgets.clear()
        self._checkboxes.clear()

        deep = self._deep_scan_var.get()
        use_proxy = self._is_vpn_connected() if self._is_vpn_connected else False

        # Update proxy status label
        if use_proxy:
            self._proxy_label.configure(
                text="🔒 Запросы через VLESS-прокси",
                text_color=("#1a7a1a", "#22cc22"),
            )
        else:
            self._proxy_label.configure(
                text="🌐 Прямое соединение (подключите VPN для заблокированных сайтов)",
                text_color=("gray50", "gray60"),
            )

        discover_domains_async(
            self._domain,
            callback=lambda domains, err: self.after(
                0, self._on_scan_done, domains, err,
            ),
            timeout=20,
            follow_subresources=deep,
            use_proxy=use_proxy,
        )

    def _on_scan_done(self, domains: list[str], error: Optional[str]) -> None:
        """Called on the main thread when scanning finishes."""
        self._progress.stop()
        self._progress.pack_forget()

        if error:
            self._status_label.configure(
                text=f"⚠ {error}",
                text_color=("#cc0000", "#ff6666"),
            )
            if not domains:
                return

        count = len(domains)
        self._status_label.configure(
            text=f"✓ Найдено {count} домен(ов)",
            text_color=("#1a7a1a", "#22cc22"),
        )
        self._count_label.configure(text=f"{count} домен(ов)")

        # Build checkbox list
        for domain in domains:
            var = ctk.BooleanVar(value=True)
            self._checkboxes[domain] = var

            row = ctk.CTkFrame(self._domain_list, corner_radius=6, height=32)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)

            cb = ctk.CTkCheckBox(
                row, text=f"🌐  {domain}",
                variable=var,
                height=24, checkbox_width=20, checkbox_height=20,
                font=ctk.CTkFont(size=11),
                command=self._update_add_btn,
            )
            cb.pack(side="left", padx=8, pady=2)
            self._list_widgets.append(row)

        self._update_add_btn()

    def _toggle_select_all(self) -> None:
        val = self._select_all_var.get()
        for var in self._checkboxes.values():
            var.set(val)
        self._update_add_btn()

    def _update_add_btn(self) -> None:
        selected = sum(1 for v in self._checkboxes.values() if v.get())
        if selected > 0:
            self._add_btn.configure(
                state="normal",
                text=f"Добавить выбранные ({selected})",
            )
        else:
            self._add_btn.configure(state="disabled", text="Добавить выбранные")

    def _confirm(self) -> None:
        selected = [d for d, v in self._checkboxes.items() if v.get()]
        if self._on_add and selected:
            self._on_add(selected)
        self.destroy()


# ======================================================================
# Login Dialog
# ======================================================================

class LoginDialog(ctk.CTkToplevel):
    """Modal login dialog — supports token or login+password auth."""

    WIDTH = 460
    HEIGHT = 480

    def __init__(
        self,
        master,
        auth_manager: "AuthManager",
        settings: Optional["AppSettings"] = None,
        on_success: Optional[Callable[[], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ):
        super().__init__(master)
        self._auth = auth_manager
        self._settings = settings
        self._on_success = on_success
        self._on_cancel = on_cancel

        self.title("Авторизация — GovnoVPN")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        # Prevent closing via X — must use Cancel or login
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 24, "pady": (6, 0)}

        ctk.CTkLabel(
            self, text="🔐  Авторизация",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(pady=(24, 4))

        ctk.CTkLabel(
            self,
            text="Введите данные для входа",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray60"),
        ).pack(pady=(0, 12))

        # ---- Server URL ---------------------------------------------------
        ctk.CTkLabel(self, text="Сервер авторизации", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._server_entry = ctk.CTkEntry(
            self, placeholder_text="https://auth.example.com", height=36,
        )
        self._server_entry.pack(fill="x", **pad)
        # Pre-fill from settings
        if self._settings and self._settings.auth_server_url:
            self._server_entry.insert(0, self._settings.auth_server_url)

        # ---- Auth mode tabs -----------------------------------------------
        self._tab_view = ctk.CTkTabview(self, height=180)
        self._tab_view.pack(fill="x", padx=24, pady=(12, 0))

        # Tab: Token
        tab_token = self._tab_view.add("Токен")
        ctk.CTkLabel(tab_token, text="API Токен", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(4, 0))
        self._token_entry = ctk.CTkEntry(
            tab_token, placeholder_text="Вставьте токен…", height=36, show="•",
        )
        self._token_entry.pack(fill="x", pady=(4, 0))

        # Tab: Login + Password
        tab_creds = self._tab_view.add("Логин / Пароль")
        ctk.CTkLabel(tab_creds, text="Логин", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(4, 0))
        self._user_entry = ctk.CTkEntry(
            tab_creds, placeholder_text="username", height=36,
        )
        self._user_entry.pack(fill="x", pady=(4, 0))

        ctk.CTkLabel(tab_creds, text="Пароль", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(8, 0))
        self._pass_entry = ctk.CTkEntry(
            tab_creds, placeholder_text="••••••••", height=36, show="•",
        )
        self._pass_entry.pack(fill="x", pady=(4, 0))

        # ---- Status label -------------------------------------------------
        self._status_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12),
            text_color=("#cc0000", "#ff6666"),
        )
        self._status_label.pack(pady=(8, 0))

        # ---- Buttons ------------------------------------------------------
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=24, pady=(12, 20))

        self._login_btn = ctk.CTkButton(
            btn_frame, text="Войти", width=140, height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._do_login,
        )
        self._login_btn.pack(side="right", padx=(8, 0))

        ctk.CTkButton(
            btn_frame, text="Отмена", width=100, height=40,
            fg_color=("gray65", "gray40"), hover_color=("gray55", "gray50"),
            command=self._cancel,
        ).pack(side="right")

    def _do_login(self) -> None:
        server = self._server_entry.get().strip()
        if not server:
            self._status_label.configure(text="Укажите адрес сервера авторизации")
            return

        # Persist server URL
        if self._settings:
            self._settings.auth_server_url = server

        current_tab = self._tab_view.get()
        self._login_btn.configure(state="disabled", text="…")
        self._status_label.configure(text="Подключение…", text_color=("gray50", "gray60"))

        def _worker():
            if current_tab == "Токен":
                token = self._token_entry.get().strip()
                if not token:
                    self.after(0, self._login_error, "Введите токен")
                    return
                ok, msg = self._auth.login_with_token(server, token)
            else:
                username = self._user_entry.get().strip()
                password = self._pass_entry.get().strip()
                if not username or not password:
                    self.after(0, self._login_error, "Введите логин и пароль")
                    return
                ok, msg = self._auth.login_with_credentials(server, username, password)

            if ok:
                self.after(0, self._login_success, msg)
            else:
                self.after(0, self._login_error, msg)

        threading.Thread(target=_worker, daemon=True).start()

    def _login_success(self, msg: str) -> None:
        self._status_label.configure(
            text=f"✓ {msg}",
            text_color=("#1a7a1a", "#22cc22"),
        )
        self._login_btn.configure(state="normal", text="Войти")
        if self._on_success:
            self._on_success()
        self.destroy()

    def _login_error(self, msg: str) -> None:
        self._status_label.configure(
            text=msg,
            text_color=("#cc0000", "#ff6666"),
        )
        self._login_btn.configure(state="normal", text="Войти")

    def _cancel(self) -> None:
        if self._on_cancel:
            self._on_cancel()
        self.destroy()


# ======================================================================
# Subscription Dialog
# ======================================================================

class SubscriptionDialog(ctk.CTkToplevel):
    """Dialog for adding a subscription URL."""

    WIDTH = 480
    HEIGHT = 260

    def __init__(
        self,
        master,
        on_save: Optional[Callable[[str, str], None]] = None,
    ):
        super().__init__(master)
        self._on_save = on_save

        self.title("Добавить подписку")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 20, "pady": (6, 0)}

        ctk.CTkLabel(
            self, text="📡  Новая подписка",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(pady=(20, 8))

        ctk.CTkLabel(self, text="Название (необязательно)", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._name_entry = ctk.CTkEntry(self, placeholder_text="Мой провайдер", height=36)
        self._name_entry.pack(fill="x", **pad)

        ctk.CTkLabel(self, text="Ссылка на подписку", font=ctk.CTkFont(size=12)).pack(anchor="w", **pad)
        self._url_entry = ctk.CTkEntry(self, placeholder_text="https://example.com/sub/...", height=36)
        self._url_entry.pack(fill="x", **pad)

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(16, 16))
        ctk.CTkButton(
            btn_frame, text="Отмена", width=100, height=38,
            fg_color=("gray65", "gray40"), hover_color=("gray55", "gray50"),
            command=self.destroy,
        ).pack(side="right", padx=(8, 0))
        ctk.CTkButton(
            btn_frame, text="Добавить", width=100, height=38,
            command=self._save,
        ).pack(side="right")

    def _save(self) -> None:
        url = self._url_entry.get().strip()
        if not url:
            return
        name = self._name_entry.get().strip()
        if self._on_save:
            self._on_save(name, url)
        self.destroy()