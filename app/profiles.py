"""
Profile & configuration management for GovnoVPN.

Handles VLESS profile storage and generation of sing-box JSON configs.
"""

import json
import re
import uuid
import base64
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

import requests


@dataclass
class VlessProfile:
    """Represents a single VLESS connection profile."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    address: str = ""
    port: int = 443
    uuid: str = ""
    flow: str = ""                     # e.g. "xtls-rprx-vision"
    encryption: str = "none"
    network: str = "tcp"               # tcp / ws / grpc / http
    security: str = "tls"              # tls / reality / none
    sni: str = ""
    fingerprint: str = "chrome"
    public_key: str = ""               # Reality pbk
    short_id: str = ""                 # Reality sid
    path: str = ""                     # WS path
    host: str = ""                     # WS / HTTP host header
    service_name: str = ""             # gRPC service name
    alpn: str = ""                     # comma-separated
    allow_insecure: bool = False

    def display_name(self) -> str:
        return self.name or f"{self.address}:{self.port}"


# ---------------------------------------------------------------------------
# VLESS URL parser  (vless://uuid@host:port?params#name)
# ---------------------------------------------------------------------------

def parse_vless_url(url: str) -> Optional[VlessProfile]:
    """Parse a vless:// URL into a VlessProfile."""
    url = url.strip()
    if not url.lower().startswith("vless://"):
        return None
    try:
        # Replace vless:// with https:// so urlparse works
        fake = "https://" + url[8:]
        parsed = urlparse(fake)
        qs = parse_qs(parsed.query)

        def first(key: str, default: str = "") -> str:
            return qs.get(key, [default])[0]

        profile = VlessProfile(
            name=unquote(parsed.fragment) if parsed.fragment else "",
            address=parsed.hostname or "",
            port=parsed.port or 443,
            uuid=parsed.username or "",
            flow=first("flow"),
            encryption=first("encryption", "none"),
            network=first("type", "tcp"),
            security=first("security", "tls"),
            sni=first("sni"),
            fingerprint=first("fp", "chrome"),
            public_key=first("pbk"),
            short_id=first("sid"),
            path=unquote(first("path")),
            host=first("host"),
            service_name=first("serviceName"),
            alpn=first("alpn"),
            allow_insecure=first("allowInsecure") == "1",
        )
        return profile
    except Exception:
        return None


def profile_to_vless_url(p: VlessProfile) -> str:
    """Serialize a VlessProfile back to a vless:// URL."""
    params = []
    if p.encryption and p.encryption != "none":
        params.append(f"encryption={p.encryption}")
    if p.flow:
        params.append(f"flow={p.flow}")
    if p.security:
        params.append(f"security={p.security}")
    if p.network and p.network != "tcp":
        params.append(f"type={p.network}")
    else:
        params.append("type=tcp")
    if p.sni:
        params.append(f"sni={p.sni}")
    if p.fingerprint:
        params.append(f"fp={p.fingerprint}")
    if p.public_key:
        params.append(f"pbk={p.public_key}")
    if p.short_id:
        params.append(f"sid={p.short_id}")
    if p.path:
        params.append(f"path={p.path}")
    if p.host:
        params.append(f"host={p.host}")
    if p.service_name:
        params.append(f"serviceName={p.service_name}")
    if p.alpn:
        params.append(f"alpn={p.alpn}")

    query = "&".join(params)
    fragment = p.name or ""
    return f"vless://{p.uuid}@{p.address}:{p.port}?{query}#{fragment}"


# ---------------------------------------------------------------------------
# sing-box JSON config builder
# ---------------------------------------------------------------------------

def build_singbox_config(
    profile: VlessProfile,
    whitelist_domains: Optional[List[str]] = None,
    whitelist_processes: Optional[List[str]] = None,
) -> dict:
    """Generate a sing-box JSON configuration for a given VLESS profile.

    If *whitelist_domains* or *whitelist_processes* is provided and non-empty,
    only traffic matching those rules is routed through the proxy;
    everything else goes direct.
    """

    # -- Outbound ----------------------------------------------------------
    outbound: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": profile.address,
        "server_port": profile.port,
        "uuid": profile.uuid,
        "flow": profile.flow or "",
    }

    # TLS settings
    if profile.security in ("tls", "reality"):
        tls: dict = {
            "enabled": True,
            "server_name": profile.sni or profile.address,
            "insecure": profile.allow_insecure,
        }
        if profile.fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": profile.fingerprint}
        if profile.alpn:
            tls["alpn"] = [a.strip() for a in profile.alpn.split(",") if a.strip()]

        if profile.security == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": profile.public_key,
                "short_id": profile.short_id,
            }

        outbound["tls"] = tls

    # Transport settings
    if profile.network == "ws":
        outbound["transport"] = {
            "type": "ws",
            "path": profile.path or "/",
            "headers": {"Host": profile.host} if profile.host else {},
        }
    elif profile.network == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": profile.service_name or "",
        }
    elif profile.network == "http":
        transport: dict = {"type": "http"}
        if profile.host:
            transport["host"] = [profile.host]
        if profile.path:
            transport["path"] = profile.path
        outbound["transport"] = transport

    # Remove empty flow
    if not outbound.get("flow"):
        outbound.pop("flow", None)

    # -- Full config -------------------------------------------------------
    config = {
        "log": {"level": "debug", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "proxy-dns",
                    "type": "https",
                    "server": "1.1.1.1",
                    "server_port": 443,
                    "detour": "proxy",
                },
                {
                    "tag": "direct-dns",
                    "type": "udp",
                    "server": "8.8.8.8",
                    "server_port": 53,
                    "detour": "direct",
                },
            ],
            "final": "proxy-dns",
            "strategy": "prefer_ipv4",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "govnovpn-tun",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniff": True,
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True,
            },
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct", "domain_resolver": "direct-dns"},
        ],
        "route": {
            "rules": [
                {"action": "hijack-dns", "protocol": "dns"},
                {"action": "route", "ip_is_private": True, "outbound": "direct"},
            ],
            "auto_detect_interface": True,
            "default_domain_resolver": "direct-dns",
            "final": "proxy",
        },
    }

    # ---- Whitelist mode: only listed domains/processes go via proxy ------
    has_domains = bool(whitelist_domains)
    has_processes = bool(whitelist_processes)

    if has_domains or has_processes:
        # Default goes direct in whitelist mode
        config["route"]["final"] = "direct"

        if has_domains:
            # Normalize: strip, lowercase, remove empties
            domains = sorted({d.strip().lower() for d in whitelist_domains if d.strip()})
            if domains:
                domain_suffixes = []
                for d in domains:
                    if d.startswith("."):
                        domain_suffixes.append(d[1:])
                    else:
                        domain_suffixes.append(d)

                proxy_rule_domain: dict = {
                    "action": "route",
                    "outbound": "proxy",
                    "domain_suffix": domain_suffixes,
                }
                config["route"]["rules"].append(proxy_rule_domain)

                # DNS rule: resolve whitelisted domains via proxy-dns
                dns_rule: dict = {"action": "route", "server": "proxy-dns", "domain_suffix": domain_suffixes}
                config["dns"]["rules"] = [dns_rule]

        if has_processes:
            # Normalize process names
            procs = sorted({p.strip() for p in whitelist_processes if p.strip()})
            if procs:
                proxy_rule_proc: dict = {
                    "action": "route",
                    "outbound": "proxy",
                    "process_name": procs,
                }
                config["route"]["rules"].append(proxy_rule_proc)

    # Add domain_resolver to outbound so sing-box can resolve the server address
    outbound["domain_resolver"] = "direct-dns"

    return config


# ---------------------------------------------------------------------------
# Persistence — store profiles to disk
# ---------------------------------------------------------------------------

class ProfileStore:
    """Load / save profiles to a JSON file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.profiles: List[VlessProfile] = []
        self.active_id: Optional[str] = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text("utf-8"))
            self.active_id = data.get("active_id")
            for item in data.get("profiles", []):
                p = VlessProfile(**{
                    k: v for k, v in item.items()
                    if k in VlessProfile.__dataclass_fields__
                })
                self.profiles.append(p)
        except Exception:
            pass

    def save(self) -> None:
        data = {
            "active_id": self.active_id,
            "profiles": [asdict(p) for p in self.profiles],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")

    def add(self, profile: VlessProfile) -> None:
        self.profiles.append(profile)
        if self.active_id is None:
            self.active_id = profile.id
        self.save()

    def remove(self, profile_id: str) -> None:
        self.profiles = [p for p in self.profiles if p.id != profile_id]
        if self.active_id == profile_id:
            self.active_id = self.profiles[0].id if self.profiles else None
        self.save()

    def get_active(self) -> Optional[VlessProfile]:
        if not self.active_id:
            return None
        for p in self.profiles:
            if p.id == self.active_id:
                return p
        return None

    def set_active(self, profile_id: str) -> None:
        self.active_id = profile_id
        self.save()

    def update(self, profile: VlessProfile) -> None:
        for i, p in enumerate(self.profiles):
            if p.id == profile.id:
                self.profiles[i] = profile
                break
        self.save()


# ---------------------------------------------------------------------------
# Domain whitelist — split-tunneling by domain
# ---------------------------------------------------------------------------

class DomainWhitelist:
    """Persists a list of domains and processes that should be routed through the proxy.

    When the whitelist is *enabled* and non-empty, only matching traffic
    goes through VLESS; everything else is direct.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.enabled: bool = False
        self.domains: List[str] = []
        self.processes: List[str] = []  # e.g. ["chrome.exe", "firefox.exe"]
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text("utf-8"))
            self.enabled = bool(data.get("enabled", False))
            self.domains = list(data.get("domains", []))
            self.processes = list(data.get("processes", []))
        except Exception:
            pass

    def save(self) -> None:
        data = {
            "enabled": self.enabled,
            "domains": self.domains,
            "processes": self.processes,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")

    # ---- Domain management -----------------------------------------------
    def add(self, domain: str) -> None:
        d = domain.strip().lower()
        if d and d not in self.domains:
            self.domains.append(d)
            self.save()

    def remove(self, domain: str) -> None:
        d = domain.strip().lower()
        self.domains = [x for x in self.domains if x != d]
        self.save()

    # ---- Process management ----------------------------------------------
    def add_process(self, name: str) -> None:
        n = name.strip()
        if n and n not in self.processes:
            self.processes.append(n)
            self.save()

    def remove_process(self, name: str) -> None:
        self.processes = [x for x in self.processes if x != name]
        self.save()

    # ---- Toggle ----------------------------------------------------------
    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        self.save()

    def get_active_domains(self) -> Optional[List[str]]:
        """Return the domain list if whitelist is enabled, else None."""
        if self.enabled and self.domains:
            return list(self.domains)
        return None

    def get_active_processes(self) -> Optional[List[str]]:
        """Return the process list if whitelist is enabled, else None."""
        if self.enabled and self.processes:
            return list(self.processes)
        return None


# ---------------------------------------------------------------------------
# Subscription support — fetch VLESS profiles from a remote URL
# ---------------------------------------------------------------------------

def _decode_subscription_content(raw: str) -> List[str]:
    """Decode subscription content.

    Subscriptions are usually base64-encoded text with one URI per line.
    Some providers return plain text directly.
    Returns a list of individual URI strings.
    """
    raw = raw.strip()
    # Try base64 decode first
    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8", errors="ignore").strip()
        # Heuristic: if decoded text looks like vless:// lines, use it
        if "vless://" in decoded.lower():
            return [ln.strip() for ln in decoded.splitlines() if ln.strip()]
    except Exception:
        pass
    # Fallback: treat as plain text
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def fetch_subscription(url: str, timeout: int = 20) -> Tuple[List[VlessProfile], str]:
    """Fetch a subscription URL and parse VLESS profiles.

    Returns (profiles, info_string).
    info_string contains the subscription-info header or server name.
    """
    url = url.strip()
    if not url:
        return [], "Пустой URL"
    try:
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "GovnoVPN/1.0",
        })
        resp.raise_for_status()
    except requests.ConnectionError:
        return [], "Не удалось подключиться"
    except requests.Timeout:
        return [], "Тайм-аут запроса"
    except requests.HTTPError as e:
        return [], f"HTTP ошибка: {e.response.status_code}"
    except Exception as e:
        return [], f"Ошибка: {e}"

    # Parse subscription-userinfo header if present
    info = resp.headers.get("subscription-userinfo", "")

    lines = _decode_subscription_content(resp.text)
    profiles: List[VlessProfile] = []
    for line in lines:
        if line.lower().startswith("vless://"):
            p = parse_vless_url(line)
            if p is not None:
                profiles.append(p)
    if not profiles:
        return [], "Не найдено VLESS серверов"
    return profiles, info


@dataclass
class Subscription:
    """A subscription — a remote URL that provides VLESS profile links."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    url: str = ""
    enabled: bool = True
    last_update: float = 0.0        # UNIX timestamp
    last_count: int = 0             # number of profiles at last fetch
    info: str = ""                  # subscription-userinfo header
    profile_ids: List[str] = field(default_factory=list)  # IDs of profiles from this sub


class SubscriptionStore:
    """Persist and manage subscriptions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.subscriptions: List[Subscription] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text("utf-8"))
            for item in data.get("subscriptions", []):
                s = Subscription(
                    id=item.get("id", str(uuid.uuid4())[:8]),
                    name=item.get("name", ""),
                    url=item.get("url", ""),
                    enabled=item.get("enabled", True),
                    last_update=item.get("last_update", 0.0),
                    last_count=item.get("last_count", 0),
                    info=item.get("info", ""),
                    profile_ids=item.get("profile_ids", []),
                )
                self.subscriptions.append(s)
        except Exception:
            pass

    def save(self) -> None:
        data = {"subscriptions": [asdict(s) for s in self.subscriptions]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")

    def add(self, sub: Subscription) -> None:
        self.subscriptions.append(sub)
        self.save()

    def remove(self, sub_id: str) -> None:
        self.subscriptions = [s for s in self.subscriptions if s.id != sub_id]
        self.save()

    def get(self, sub_id: str) -> Optional[Subscription]:
        for s in self.subscriptions:
            if s.id == sub_id:
                return s
        return None

    def update_sub(self, sub: Subscription) -> None:
        for i, s in enumerate(self.subscriptions):
            if s.id == sub.id:
                self.subscriptions[i] = sub
                break
        self.save()

    def refresh(self, sub: Subscription, profile_store: "ProfileStore") -> Tuple[bool, str]:
        """Fetch new profiles for a subscription, update the profile store.

        Removes old profiles from this subscription and adds fresh ones.
        Returns (success, message).
        """
        profiles, info = fetch_subscription(sub.url)
        if not profiles:
            return False, info

        # Remove old profiles belonging to this subscription
        for pid in sub.profile_ids:
            profile_store.remove(pid)

        # Add fetched profiles, tag them with unique IDs
        new_ids = []
        for p in profiles:
            p.id = str(uuid.uuid4())[:8]
            profile_store.profiles.append(p)
            new_ids.append(p.id)

        # Set first profile as active if nothing is active
        if profile_store.active_id is None and new_ids:
            profile_store.active_id = new_ids[0]
        profile_store.save()

        # Update subscription metadata
        sub.profile_ids = new_ids
        sub.last_update = time.time()
        sub.last_count = len(profiles)
        sub.info = info
        self.update_sub(sub)

        return True, f"Загружено {len(profiles)} сервер(ов)"
