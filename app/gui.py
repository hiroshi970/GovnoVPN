"""
Main application window for GovnoVPN.

Modern, theme-adaptive GUI built with CustomTkinter.
"""

import re
import threading
import time
import tkinter as tk
from typing import Optional

from PIL import Image, ImageDraw

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

import customtkinter as ctk


def _make_poop_image(size: int = 64, color: tuple = (139, 90, 43)) -> Image.Image:
    """Generate a compact poop emoji image with Pillow."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s = size / 64  # scale factor

    dark = (max(0, color[0] - 38), max(0, color[1] - 23), max(0, color[2] - 10))

    # Wide base
    draw.ellipse([int(6*s), int(34*s), int(58*s), int(60*s)], fill=color, outline=dark)
    # Middle body (wide)
    draw.ellipse([int(10*s), int(22*s), int(54*s), int(48*s)], fill=color, outline=dark)
    # Top swirl (small, centered)
    draw.ellipse([int(22*s), int(12*s), int(42*s), int(30*s)], fill=color, outline=dark)
    # Tip
    draw.ellipse([int(28*s), int(6*s), int(38*s), int(18*s)], fill=color, outline=dark)

    # Eyes
    draw.ellipse([int(22*s), int(30*s), int(30*s), int(38*s)], fill="white")
    draw.ellipse([int(34*s), int(30*s), int(42*s), int(38*s)], fill="white")
    draw.ellipse([int(24*s), int(32*s), int(28*s), int(36*s)], fill="black")
    draw.ellipse([int(36*s), int(32*s), int(40*s), int(36*s)], fill="black")

    # Smile
    draw.arc([int(24*s), int(38*s), int(40*s), int(48*s)], start=0, end=180, fill="black", width=max(1, int(2*s)))

    return img

from app import __app_name__, __version__
from app.singbox import SingBoxManager
from app.profiles import (
    ProfileStore,
    VlessProfile,
    DomainWhitelist,
    build_singbox_config,
    Subscription,
    SubscriptionStore,
)
from app.auth import AuthManager
from app.settings import AppSettings
from app.streamer import (
    mask_address, mask_port, mask_log_line,
    mask_profile_detail, mask_display_name,
)
from app.dialogs import ProfileDialog, AboutDialog, SettingsDialog, LogDialog, WhitelistDialog, LoginDialog, SubscriptionDialog


# ======================================================================
# Main Window
# ======================================================================

class GovnoVPNApp(ctk.CTk):
    """Root application window."""

    WIDTH = 520
    HEIGHT = 820

    def __init__(self) -> None:
        # Pre-load settings & set color theme BEFORE creating the window
        # (ctk.set_default_color_theme must be called before CTk.__init__)
        _singbox = SingBoxManager()
        _settings = AppSettings(_singbox.data_dir / "settings.json")

        ctk.set_default_color_theme(_settings.get("color_theme", "blue"))
        ctk.set_appearance_mode(_settings.get("theme", "system"))

        super().__init__()

        # Core services
        self._singbox = _singbox
        self._store = ProfileStore(self._singbox.data_dir / "profiles.json")
        self._whitelist = DomainWhitelist(self._singbox.data_dir / "whitelist.json")
        self._sub_store = SubscriptionStore(self._singbox.data_dir / "subscriptions.json")
        self._settings = _settings
        self._auth = AuthManager(self._singbox.data_dir)
        self._log_dialog: Optional[LogDialog] = None
        self._log_buffer: list[str] = []  # buffer all log lines
        self._streamer_mode: bool = self._settings.streamer_mode

        # ---- Window chrome ------------------------------------------------
        self.title(f"{__app_name__} v{__version__}")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        self.minsize(420, 650)

        # Callbacks
        self._singbox.set_callbacks(
            on_status_change=lambda s: self.after(0, self._set_status, s),
            on_log=lambda l: self.after(0, self._append_log, l),
        )

        self._build_ui()
        self._refresh_profiles()
        self._check_singbox()
        self._update_auth_ui()
        # Auto-update subscriptions on startup
        self.after(1000, self._auto_update_subscriptions)

    # ==================================================================
    # UI construction
    # ==================================================================

    def _build_ui(self) -> None:
        # ---- Top bar (logo + settings) -----------------------------------
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(16, 0))

        self._title_poop_img = ctk.CTkImage(
            light_image=_make_poop_image(32, (139, 90, 43)),
            dark_image=_make_poop_image(32, (139, 90, 43)),
            size=(28, 28),
        )
        ctk.CTkLabel(
            top,
            text=f"  {__app_name__}",
            image=self._title_poop_img,
            compound="left",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).pack(side="left")

        btn_row = ctk.CTkFrame(top, fg_color="transparent")
        btn_row.pack(side="right")
        ctk.CTkButton(btn_row, text="⚙", width=36, height=36, font=ctk.CTkFont(size=16),
                       fg_color="transparent", hover_color=("gray85", "gray25"),
                       text_color=("gray10", "gray90"),
                       command=self._open_settings).pack(side="left", padx=2)
        ctk.CTkButton(btn_row, text="📋", width=36, height=36, font=ctk.CTkFont(size=16),
                       fg_color="transparent", hover_color=("gray85", "gray25"),
                       text_color=("gray10", "gray90"),
                       command=self._open_logs).pack(side="left", padx=2)
        ctk.CTkButton(btn_row, text="ℹ", width=36, height=36, font=ctk.CTkFont(size=16),
                       fg_color="transparent", hover_color=("gray85", "gray25"),
                       text_color=("gray10", "gray90"),
                       command=self._open_about).pack(side="left", padx=2)

        # ---- Auth status row -----------------------------------------------
        auth_row = ctk.CTkFrame(self, fg_color="transparent")
        auth_row.pack(fill="x", padx=20, pady=(8, 0))

        self._auth_label = ctk.CTkLabel(
            auth_row, text="",
            font=ctk.CTkFont(size=11),
            text_color=("gray50", "gray60"),
        )
        self._auth_label.pack(side="left")

        self._auth_btn = ctk.CTkButton(
            auth_row, text="Войти", width=80, height=26,
            font=ctk.CTkFont(size=11),
            command=self._show_login,
        )
        self._auth_btn.pack(side="right")

        # Streamer mode indicator
        self._streamer_badge = ctk.CTkLabel(
            auth_row, text="🎥 Стример",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#cc6600", "#ffaa33"),
        )
        # shown only when streamer mode active
        if self._streamer_mode:
            self._streamer_badge.pack(side="right", padx=(0, 8))

        # ---- Status card --------------------------------------------------
        self._status_card = ctk.CTkFrame(self, corner_radius=16)
        self._status_card.pack(fill="x", padx=20, pady=(16, 0))

        self._poop_img = ctk.CTkImage(
            light_image=_make_poop_image(128, (139, 90, 43)),
            dark_image=_make_poop_image(128, (139, 90, 43)),
            size=(64, 64),
        )
        self._poop_connected_img = ctk.CTkImage(
            light_image=_make_poop_image(128, (34, 197, 94)),
            dark_image=_make_poop_image(128, (34, 197, 94)),
            size=(64, 64),
        )
        self._poop_error_img = ctk.CTkImage(
            light_image=_make_poop_image(128, (200, 50, 50)),
            dark_image=_make_poop_image(128, (200, 50, 50)),
            size=(64, 64),
        )
        self._poop_connecting_img = ctk.CTkImage(
            light_image=_make_poop_image(128, (200, 180, 50)),
            dark_image=_make_poop_image(128, (200, 180, 50)),
            size=(64, 64),
        )
        self._status_emoji = ctk.CTkLabel(
            self._status_card, text="", image=self._poop_img,
        )
        self._status_emoji.pack(pady=(24, 4))

        self._status_label = ctk.CTkLabel(
            self._status_card, text="Отключено",
            font=ctk.CTkFont(size=17, weight="bold"),
        )
        self._status_label.pack()

        self._status_detail = ctk.CTkLabel(
            self._status_card, text="Готов к подключению",
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray60"),
        )
        self._status_detail.pack(pady=(0, 4))

        # Connect / Disconnect button
        self._connect_btn = ctk.CTkButton(
            self._status_card,
            text="Подключиться",
            height=44,
            corner_radius=22,
            font=ctk.CTkFont(size=15, weight="bold"),
            command=self._toggle_connection,
        )
        self._connect_btn.pack(fill="x", padx=32, pady=(12, 24))

        # ---- sing-box status row ------------------------------------------
        sb_row = ctk.CTkFrame(self, fg_color="transparent")
        sb_row.pack(fill="x", padx=20, pady=(12, 0))
        self._sb_label = ctk.CTkLabel(sb_row, text="sing-box: проверка…", font=ctk.CTkFont(size=12),
                                       text_color=("gray50", "gray60"))
        self._sb_label.pack(side="left")
        self._sb_download_btn = ctk.CTkButton(
            sb_row, text="Скачать", width=80, height=28,
            font=ctk.CTkFont(size=11), command=self._download_singbox,
        )
        # will be shown only if sing-box missing

        # ---- Whitelist row -----------------------------------------------
        wl_row = ctk.CTkFrame(self, fg_color="transparent")
        wl_row.pack(fill="x", padx=20, pady=(8, 0))

        self._wl_status = ctk.CTkLabel(
            wl_row,
            text=self._whitelist_status_text(),
            font=ctk.CTkFont(size=12),
            text_color=("gray50", "gray60"),
        )
        self._wl_status.pack(side="left")

        ctk.CTkButton(
            wl_row, text="Белый список", width=110, height=28,
            font=ctk.CTkFont(size=11),
            command=self._open_whitelist,
        ).pack(side="right")

        # ---- Subscriptions section ----------------------------------------
        sub_header = ctk.CTkFrame(self, fg_color="transparent")
        sub_header.pack(fill="x", padx=20, pady=(12, 2))
        ctk.CTkLabel(sub_header, text="Подписки", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")

        sub_btn_row = ctk.CTkFrame(sub_header, fg_color="transparent")
        sub_btn_row.pack(side="right")
        self._sub_update_all_btn = ctk.CTkButton(
            sub_btn_row, text="🔄", width=30, height=30,
            font=ctk.CTkFont(size=14),
            fg_color="transparent", hover_color=("gray85", "gray25"),
            text_color=("gray10", "gray90"),
            command=self._update_all_subs,
        )
        self._sub_update_all_btn.pack(side="left", padx=2)
        self._add_sub_btn = ctk.CTkButton(
            sub_btn_row, text="＋ Подписка", width=110, height=30,
            font=ctk.CTkFont(size=12), command=self._add_subscription,
        )
        if not self._streamer_mode:
            self._add_sub_btn.pack(side="left", padx=2)

        self._sub_scroll = ctk.CTkScrollableFrame(self, fg_color="transparent", height=0)
        self._sub_scroll.pack(fill="x", padx=16, pady=(0, 0))
        self._sub_widgets: list = []
        self._refresh_subscriptions()

        # ---- Profile list section -----------------------------------------
        prof_header = ctk.CTkFrame(self, fg_color="transparent")
        prof_header.pack(fill="x", padx=20, pady=(8, 4))
        ctk.CTkLabel(prof_header, text="Серверы", font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        self._add_profile_btn = ctk.CTkButton(
            prof_header, text="＋ Добавить", width=110, height=30,
            font=ctk.CTkFont(size=12), command=self._add_profile,
        )
        if not self._streamer_mode:
            self._add_profile_btn.pack(side="right")

        self._profile_scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._profile_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self._profile_widgets: list = []



    # ==================================================================
    # Profile list rendering
    # ==================================================================

    def _refresh_profiles(self) -> None:
        for w in self._profile_widgets:
            w.destroy()
        self._profile_widgets.clear()

        for p in self._store.profiles:
            card = self._make_profile_card(p)
            card.pack(fill="x", pady=4)
            self._profile_widgets.append(card)

    def _make_profile_card(self, p: VlessProfile) -> ctk.CTkFrame:
        is_active = p.id == self._store.active_id

        card = ctk.CTkFrame(self._profile_scroll, corner_radius=12, height=64)
        card.pack_propagate(False)

        # Selection indicator
        accent = ctk.ThemeManager.theme["CTkButton"]["fg_color"]
        indicator_color = accent if is_active else ("gray75", "gray35")

        indicator = ctk.CTkFrame(card, width=5, corner_radius=3, fg_color=indicator_color)
        indicator.pack(side="left", fill="y", padx=(6, 0), pady=8)

        # Info column
        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=8)

        name_lbl = ctk.CTkLabel(info, text=p.display_name() if not self._streamer_mode else mask_display_name(p.name, p.address, p.port), font=ctk.CTkFont(size=13, weight="bold"), anchor="w")
        name_lbl.pack(anchor="w")

        if self._streamer_mode:
            detail_text = mask_profile_detail(p.address, p.port, p.security, p.network)
        else:
            detail_text = f"{p.address}:{p.port}  •  {p.security.upper()}"
            if p.network != "tcp":
                detail_text += f"  •  {p.network.upper()}"
        ctk.CTkLabel(info, text=detail_text, font=ctk.CTkFont(size=11),
                     text_color=("gray50", "gray60"), anchor="w").pack(anchor="w")

        # Action buttons
        btn_box = ctk.CTkFrame(card, fg_color="transparent")
        btn_box.pack(side="right", padx=8, pady=8)

        if not is_active:
            ctk.CTkButton(btn_box, text="✓", width=32, height=32,
                           font=ctk.CTkFont(size=14),
                           fg_color="transparent", hover_color=("gray85", "gray25"),
                           text_color=("gray10", "gray90"),
                           command=lambda pid=p.id: self._select_profile(pid)).pack(side="left", padx=2)

        if not self._streamer_mode:
            ctk.CTkButton(btn_box, text="✎", width=32, height=32,
                           font=ctk.CTkFont(size=14),
                           fg_color="transparent", hover_color=("gray85", "gray25"),
                           text_color=("gray10", "gray90"),
                           command=lambda profile=p: self._edit_profile(profile)).pack(side="left", padx=2)

            ctk.CTkButton(btn_box, text="✕", width=32, height=32,
                           font=ctk.CTkFont(size=14),
                           fg_color="transparent", hover_color=("#ffcccc", "#5c2020"),
                           text_color=("#cc0000", "#ff6666"),
                           command=lambda pid=p.id: self._delete_profile(pid)).pack(side="left", padx=2)

        # Click to select
        for widget in (card, info, name_lbl):
            widget.bind("<Button-1>", lambda e, pid=p.id: self._select_profile(pid))

        return card

    # ==================================================================
    # Profile actions
    # ==================================================================

    def _add_profile(self) -> None:
        ProfileDialog(self, on_save=self._on_profile_saved)

    def _edit_profile(self, profile: VlessProfile) -> None:
        ProfileDialog(self, profile=profile, on_save=self._on_profile_updated)

    def _on_profile_saved(self, profile: VlessProfile) -> None:
        self._store.add(profile)
        self._refresh_profiles()

    def _on_profile_updated(self, profile: VlessProfile) -> None:
        self._store.update(profile)
        self._refresh_profiles()

    def _select_profile(self, profile_id: str) -> None:
        self._store.set_active(profile_id)
        self._refresh_profiles()

    def _delete_profile(self, profile_id: str) -> None:
        if self._singbox.is_running:
            active = self._store.get_active()
            if active and active.id == profile_id:
                return  # don't delete an active running profile
        self._store.remove(profile_id)
        self._refresh_profiles()

    # ==================================================================
    # Subscription rendering & actions
    # ==================================================================

    def _refresh_subscriptions(self) -> None:
        for w in self._sub_widgets:
            w.destroy()
        self._sub_widgets.clear()

        subs = self._sub_store.subscriptions
        # Adjust scrollable frame height based on content
        if not subs:
            self._sub_scroll.configure(height=0)
        else:
            self._sub_scroll.configure(height=min(len(subs) * 52, 156))

        for s in subs:
            card = self._make_sub_card(s)
            card.pack(fill="x", pady=2)
            self._sub_widgets.append(card)

    def _make_sub_card(self, s: Subscription) -> ctk.CTkFrame:
        card = ctk.CTkFrame(self._sub_scroll, corner_radius=10, height=48)
        card.pack_propagate(False)

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=6)

        name_text = s.name or s.url[:40]
        ctk.CTkLabel(info_frame, text=f"📡  {name_text}",
                     font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(anchor="w")

        import datetime
        if s.last_update:
            ts = datetime.datetime.fromtimestamp(s.last_update).strftime("%d.%m %H:%M")
            detail = f"{s.last_count} сервер(ов) • обновлено {ts}"
        else:
            detail = "Не обновлялась"
        ctk.CTkLabel(info_frame, text=detail,
                     font=ctk.CTkFont(size=10), text_color=("gray50", "gray60"),
                     anchor="w").pack(anchor="w")

        btn_box = ctk.CTkFrame(card, fg_color="transparent")
        btn_box.pack(side="right", padx=6, pady=6)

        ctk.CTkButton(btn_box, text="🔄", width=28, height=28,
                       font=ctk.CTkFont(size=12),
                       fg_color="transparent", hover_color=("gray85", "gray25"),
                       text_color=("gray10", "gray90"),
                       command=lambda sid=s.id: self._update_subscription(sid)).pack(side="left", padx=1)

        if not self._streamer_mode:
            ctk.CTkButton(btn_box, text="✕", width=28, height=28,
                           font=ctk.CTkFont(size=12),
                           fg_color="transparent", hover_color=("#ffcccc", "#5c2020"),
                           text_color=("#cc0000", "#ff6666"),
                           command=lambda sid=s.id: self._delete_subscription(sid)).pack(side="left", padx=1)

        return card

    def _add_subscription(self) -> None:
        SubscriptionDialog(self, on_save=self._on_sub_saved)

    def _on_sub_saved(self, name: str, url: str) -> None:
        sub = Subscription(name=name, url=url)
        self._sub_store.add(sub)
        self._refresh_subscriptions()
        # Immediately fetch
        self._update_subscription(sub.id)

    def _update_subscription(self, sub_id: str) -> None:
        sub = self._sub_store.get(sub_id)
        if sub is None:
            return
        self._append_log(f"[Подписка] Обновление «{sub.name or sub.url[:30]}»…")

        def _do():
            ok, msg = self._sub_store.refresh(sub, self._store)
            self.after(0, self._on_sub_updated, sub_id, ok, msg)

        threading.Thread(target=_do, daemon=True).start()

    def _on_sub_updated(self, sub_id: str, ok: bool, msg: str) -> None:
        sub = self._sub_store.get(sub_id)
        name = sub.name if sub else sub_id
        if ok:
            self._append_log(f"[Подписка] «{name}»: {msg}")
        else:
            self._append_log(f"[Подписка] «{name}»: ошибка — {msg}")
        self._refresh_subscriptions()
        self._refresh_profiles()

    def _delete_subscription(self, sub_id: str) -> None:
        sub = self._sub_store.get(sub_id)
        if sub is None:
            return
        # Remove profiles belonging to this subscription
        for pid in sub.profile_ids:
            self._store.remove(pid)
        self._sub_store.remove(sub_id)
        self._refresh_subscriptions()
        self._refresh_profiles()

    def _update_all_subs(self) -> None:
        for s in self._sub_store.subscriptions:
            if s.enabled:
                self._update_subscription(s.id)

    def _auto_update_subscriptions(self) -> None:
        """Auto-update all enabled subscriptions on launch."""
        for s in self._sub_store.subscriptions:
            if s.enabled:
                self._update_subscription(s.id)

    # ==================================================================
    # Connection toggle
    # ==================================================================

    def _toggle_connection(self) -> None:
        if self._singbox.is_running:
            self._disconnect()
        else:
            self._connect()

    def _connect(self) -> None:
        profile = self._store.get_active()
        if profile is None:
            self._status_detail.configure(text="Добавьте сервер для подключения")
            return

        if not self._singbox.is_installed():
            self._status_detail.configure(text="sing-box не установлен — нажмите «Скачать»")
            return

        self._set_status("connecting")
        # Build & write config, then start
        wl_domains = self._whitelist.get_active_domains()
        wl_procs = self._whitelist.get_active_processes()
        config = build_singbox_config(profile, whitelist_domains=wl_domains, whitelist_processes=wl_procs)
        self._singbox.write_config(config)
        if wl_domains or wl_procs:
            parts = []
            if wl_domains:
                parts.append(f"{len(wl_domains)} домен(ов)")
            if wl_procs:
                parts.append(f"{len(wl_procs)} процесс(ов)")
            self._append_log(f"[Белый список] {', '.join(parts)} через VLESS, остальное — напрямую")
        else:
            self._append_log("[Маршрут] Весь трафик через VLESS")
        if self._streamer_mode:
            self._append_log(f"[Конфиг] Записан: ***")
            self._append_log(f"[Запуск] sing-box run -c ***")
        else:
            self._append_log(f"[Конфиг] Записан: {self._singbox.config_path}")
            self._append_log(f"[Запуск] {self._singbox.bin_path} run -c {self._singbox.config_path}")

        if not self._singbox.start():
            self._set_status("error")
            self._status_detail.configure(text="Не удалось запустить sing-box")

    def _disconnect(self) -> None:
        self._singbox.stop()

    # ==================================================================
    # Status display
    # ==================================================================

    def _set_status(self, status: str) -> None:
        img_mapping = {
            "connected":    self._poop_connected_img,
            "disconnected": self._poop_img,
            "connecting":   self._poop_connecting_img,
            "error":        self._poop_error_img,
        }
        label_mapping = {
            "connected":    ("Подключено", "VPN-туннель активен"),
            "disconnected": ("Отключено", "Готов к подключению"),
            "connecting":   ("Подключение…", "Устанавливается соединение"),
            "error":        ("Ошибка", "Произошла ошибка"),
        }
        poop_img = img_mapping.get(status, self._poop_img)
        label, detail = label_mapping.get(status, label_mapping["disconnected"])
        self._status_emoji.configure(image=poop_img)
        self._status_label.configure(text=label)
        if status != "error":  # keep error detail from caller
            self._status_detail.configure(text=detail)

        if status == "connected":
            self._connect_btn.configure(
                text="Отключиться",
                fg_color=("#cc3333", "#aa2222"),
                hover_color=("#aa2222", "#881111"),
            )
        else:
            self._connect_btn.configure(
                text="Подключиться",
                fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"],
                hover_color=ctk.ThemeManager.theme["CTkButton"]["hover_color"],
            )

    # ==================================================================
    # sing-box management
    # ==================================================================

    def _check_singbox(self) -> None:
        if self._singbox.is_installed():
            ver = self._singbox.version() or "unknown"
            self._sb_label.configure(text=f"sing-box: {ver}")
            self._sb_download_btn.pack_forget()
            # Check for updates in background
            self.after(1500, self._check_singbox_update)
        else:
            self._sb_label.configure(text="sing-box: не найден")
            self._sb_download_btn.pack(side="right")
            # Auto-download on first launch
            self.after(500, self._download_singbox)

    def _check_singbox_update(self) -> None:
        """Check for sing-box updates in background and auto-download if available."""
        def _do():
            try:
                has_update, local_ver, remote_ver = self._singbox.check_update()
                if has_update:
                    self.after(0, self._on_update_available, local_ver, remote_ver)
            except Exception:
                pass

        threading.Thread(target=_do, daemon=True).start()

    def _on_update_available(self, local_ver: str, remote_ver: str) -> None:
        self._sb_label.configure(text=f"sing-box: обновление {remote_ver}…")
        self._append_log(f"[Обновление] Найдена новая версия sing-box: {remote_ver} (текущая: {local_ver}). Скачивание…")
        self._download_singbox()

    def _download_singbox(self) -> None:
        self._sb_download_btn.configure(state="disabled", text="…")
        self._sb_label.configure(text="sing-box: загрузка…")

        def _do() -> None:
            ok = self._singbox.download_latest(
                progress_cb=lambda p: self.after(0, self._sb_label.configure,
                                                  {"text": f"sing-box: {int(p * 100)}%"})
            )
            self.after(0, self._on_download_done, ok)

        threading.Thread(target=_do, daemon=True).start()

    def _on_download_done(self, ok: bool) -> None:
        if ok:
            self._check_singbox()
        else:
            self._sb_label.configure(text="sing-box: ошибка загрузки")
            self._sb_download_btn.configure(state="normal", text="Скачать")

    # ==================================================================
    # Logs
    # ==================================================================

    def _append_log(self, line: str) -> None:
        clean_line = _ANSI_RE.sub('', line)
        # Apply streamer mode masking to logs
        display_line = mask_log_line(clean_line) if self._streamer_mode else clean_line
        self._log_buffer.append(clean_line)
        # Keep buffer bounded
        if len(self._log_buffer) > 5000:
            self._log_buffer = self._log_buffer[-3000:]

        # Floating log dialog (if open)
        if self._log_dialog is not None and self._log_dialog.winfo_exists():
            self._log_dialog.append(display_line)

    def _open_logs(self) -> None:
        if self._log_dialog is not None and self._log_dialog.winfo_exists():
            self._log_dialog.focus()
            return
        self._log_dialog = LogDialog(self)
        # Fill with buffered logs (apply masking if streamer mode is on)
        for line in self._log_buffer:
            display = mask_log_line(line) if self._streamer_mode else line
            self._log_dialog.append(display)

    # ==================================================================
    # Dialogs
    # ==================================================================

    def _open_settings(self) -> None:
        SettingsDialog(
            self,
            settings=self._settings,
            on_streamer_toggle=self._on_streamer_toggled,
            on_reopen=lambda: self.after(50, self._open_settings),
        )

    def _on_streamer_toggled(self, enabled: bool) -> None:
        """Called when user toggles streamer mode in settings."""
        self._streamer_mode = enabled
        self._refresh_profiles()
        self._refresh_subscriptions()
        # Show/hide add buttons
        if enabled:
            self._streamer_badge.pack(side="right", padx=(0, 8))
            self._add_profile_btn.pack_forget()
            self._add_sub_btn.pack_forget()
        else:
            self._streamer_badge.pack_forget()
            self._add_profile_btn.pack(side="right")
            self._add_sub_btn.pack(side="left", padx=2)

    def _open_about(self) -> None:
        AboutDialog(self)

    def _open_whitelist(self) -> None:
        WhitelistDialog(
            self, self._whitelist,
            on_change=self._on_whitelist_changed,
            is_vpn_connected=lambda: self._singbox.is_running,
        )

    # ==================================================================
    # Auth
    # ==================================================================

    def _show_login(self) -> None:
        """Open the login dialog."""
        LoginDialog(
            self,
            auth_manager=self._auth,
            settings=self._settings,
            on_success=self._on_login_success,
            on_cancel=self._on_login_cancel,
        )

    def _on_login_success(self) -> None:
        self._update_auth_ui()

    def _on_login_cancel(self) -> None:
        pass  # user can use the app without auth, but some features may be limited

    def _update_auth_ui(self) -> None:
        """Update the auth status label and button."""
        if self._auth.is_authenticated:
            name = self._auth.display_name
            self._auth_label.configure(text=f"👤 {name}")
            self._auth_btn.configure(text="Выйти", command=self._do_logout)
        else:
            self._auth_label.configure(text="🔒 Не авторизован")
            self._auth_btn.configure(text="Войти", command=self._show_login)

    def _do_logout(self) -> None:
        self._auth.logout()
        self._update_auth_ui()

    def _on_whitelist_changed(self) -> None:
        """Called when user modifies the whitelist."""
        self._wl_status.configure(text=self._whitelist_status_text())

    def _whitelist_status_text(self) -> str:
        if self._whitelist.enabled:
            nd = len(self._whitelist.domains)
            np = len(self._whitelist.processes)
            if nd or np:
                parts = []
                if nd:
                    parts.append(f"{nd} домен(ов)")
                if np:
                    parts.append(f"{np} процесс(ов)")
                return f"⚡ Белый список: {', '.join(parts)}"
            return "⚡ Белый список: включён (пусто)"
        return "🌐 Весь трафик через VPN"

    # ==================================================================
    # Cleanup
    # ==================================================================

    def on_closing(self) -> None:
        """Graceful shutdown."""
        if self._singbox.is_running:
            self._singbox.stop()
        self.destroy()
