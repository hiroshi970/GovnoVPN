"""
Streamer mode utilities for GovnoVPN.

Provides functions to mask sensitive data (IP addresses, UUIDs,
server names, ports, VLESS URLs, etc.) so that it's safe to show
the application on stream.
"""

import re
from typing import Optional


# Regex patterns for sensitive data
_IPV4_RE = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')
_UUID_RE = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
_VLESS_URL_RE = re.compile(r'vless://[^\s]+', re.IGNORECASE)
_PORT_IN_LOG_RE = re.compile(r':(\d{2,5})\b')


def mask_ip(text: str) -> str:
    """Replace all IPv4/IPv6 addresses with asterisks."""
    text = _IPV4_RE.sub('***.***.***.***', text)
    text = _IPV6_RE.sub('****:****:****', text)
    return text


def mask_uuid(text: str) -> str:
    """Replace UUIDs with asterisks."""
    return _UUID_RE.sub('********-****-****-****-************', text)


def mask_vless_url(text: str) -> str:
    """Replace full VLESS URLs with a masked version."""
    return _VLESS_URL_RE.sub('vless://***@***:***?...#***', text)


def mask_address(address: str) -> str:
    """Mask a server address / hostname."""
    if not address:
        return address
    # IP address
    if _IPV4_RE.fullmatch(address):
        return '***.***.***.***'
    # Domain — show only TLD
    parts = address.split('.')
    if len(parts) >= 2:
        return '***.' + parts[-1]
    return '***'


def mask_port(port) -> str:
    """Mask a port number."""
    return '***'


def mask_short_id(sid: str) -> str:
    """Mask a short ID."""
    if not sid:
        return sid
    return '***'


def mask_public_key(pbk: str) -> str:
    """Mask a public key."""
    if not pbk:
        return pbk
    if len(pbk) > 6:
        return pbk[:3] + '***' + pbk[-3:]
    return '***'


def mask_sni(sni: str) -> str:
    """Mask SNI (same logic as address)."""
    return mask_address(sni)


def mask_log_line(line: str) -> str:
    """Apply all masking rules to a log line."""
    line = mask_vless_url(line)
    line = mask_uuid(line)
    line = mask_ip(line)
    return line


def mask_profile_detail(address: str, port: int, security: str, network: str) -> str:
    """Build a masked detail string for a profile card."""
    addr = mask_address(address)
    p = mask_port(port)
    detail = f"{addr}:{p}  •  {security.upper()}"
    if network != "tcp":
        detail += f"  •  {network.upper()}"
    return detail


def mask_display_name(name: str, address: str, port: int) -> str:
    """Mask the display name if it contains the raw address."""
    if not name:
        return f"{mask_address(address)}:{mask_port(port)}"
    # If name literally is the address:port, mask it
    if address in name:
        name = name.replace(address, mask_address(address))
    return name
