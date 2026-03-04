"""
Domain parser for GovnoVPN whitelist.

Fetches a website and discovers all external domains it uses
(CDN, API, analytics, fonts, media, etc.) so they can be added
to the split-tunneling whitelist automatically.
"""

import re
import ssl
import threading
from html.parser import HTMLParser
from typing import Callable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

# Domains to ignore — infrastructure / tracking that users unlikely want proxied
_IGNORE_DOMAINS: Set[str] = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "",
}

# Common schemes we care about
_SCHEMES = {"http", "https", "//"}

# Attributes that may contain URLs
_URL_ATTRS = {
    "src", "href", "action", "data-src", "data-href",
    "poster", "srcset", "data-srcset", "data-background",
    "data-lazy-src", "data-original", "content",
}

# Regex to find URLs in inline scripts / CSS
_URL_RE = re.compile(
    r"""(?:https?://|//)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)"""
    r"""(?:[/\?\#:][^\s"'<>{}|\\^`\]\)]*)?""",
)

# CSS url() pattern
_CSS_URL_RE = re.compile(
    r"""url\(\s*["']?\s*(https?://[^"'\)\s]+|//[^"'\)\s]+)\s*["']?\s*\)""",
    re.IGNORECASE,
)


def _extract_domain(url: str) -> Optional[str]:
    """Extract a clean domain from a URL string."""
    url = url.strip()
    if url.startswith("//"):
        url = "https:" + url
    if not url.startswith(("http://", "https://")):
        return None
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            host = host.lower().rstrip(".")
            # Skip IPs
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                return None
            if host not in _IGNORE_DOMAINS:
                return host
    except Exception:
        pass
    return None


class _LinkExtractor(HTMLParser):
    """HTML parser that extracts domains from tags and inline content."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.domains: Set[str] = set()
        self._in_script = False
        self._in_style = False
        self._buffer = ""

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr_dict = dict(attrs)

        if tag == "script":
            self._in_script = True
            self._buffer = ""
        elif tag == "style":
            self._in_style = True
            self._buffer = ""

        # Check URL-bearing attributes
        for attr_name in _URL_ATTRS:
            val = attr_dict.get(attr_name, "")
            if not val:
                continue

            # srcset has special format: "url 1x, url 2x, ..."
            if attr_name in ("srcset", "data-srcset"):
                for part in val.split(","):
                    src = part.strip().split()[0] if part.strip() else ""
                    if src:
                        self._add_url(src)
            else:
                self._add_url(val)

        # <link> preconnect / dns-prefetch
        if tag == "link":
            rel = attr_dict.get("rel", "")
            href = attr_dict.get("href", "")
            if rel in ("preconnect", "dns-prefetch") and href:
                self._add_url(href)

        # <meta> http-equiv=refresh or og: tags
        if tag == "meta":
            content = attr_dict.get("content", "")
            if content:
                self._scan_for_urls(content)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            self._scan_for_urls(self._buffer)
            self._buffer = ""
        elif tag == "style" and self._in_style:
            self._in_style = False
            self._scan_for_urls(self._buffer)
            self._buffer = ""

    def handle_data(self, data: str) -> None:
        if self._in_script or self._in_style:
            self._buffer += data

    def _add_url(self, url: str) -> None:
        url = url.strip()
        if url.startswith("data:") or url.startswith("javascript:") or url.startswith("mailto:"):
            return
        # Resolve relative URLs
        if not url.startswith(("http://", "https://", "//")):
            url = urljoin(self.base_url, url)
        domain = _extract_domain(url)
        if domain:
            self.domains.add(domain)

    def _scan_for_urls(self, text: str) -> None:
        """Extract domains from free-form text (JS, CSS, etc.)."""
        for m in _URL_RE.finditer(text):
            domain = m.group(1).lower().rstrip(".")
            if domain and domain not in _IGNORE_DOMAINS:
                # Basic TLD check — at least one dot
                if "." in domain:
                    self.domains.add(domain)
        for m in _CSS_URL_RE.finditer(text):
            d = _extract_domain(m.group(1))
            if d:
                self.domains.add(d)


def _get_root_domain(domain: str) -> str:
    """Get 2nd-level domain.  e.g.  'cdn.example.com' -> 'example.com'."""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


# Default local proxy address used by sing-box mixed inbound
_LOCAL_PROXY = "socks5://127.0.0.1:2080"


def discover_domains(
    domain: str,
    *,
    timeout: int = 15,
    follow_subresources: bool = False,
    use_proxy: bool = False,
) -> Tuple[List[str], Optional[str]]:
    """Fetch a website and discover all domains it references.

    Parameters
    ----------
    domain : str
        The domain to analyze (e.g. ``youtube.com``).
    timeout : int
        HTTP request timeout in seconds.
    follow_subresources : bool
        If True, also fetch discovered CSS/JS files to find more domains
        (slower but more thorough).
    use_proxy : bool
        If True, route requests through the local sing-box SOCKS5 proxy
        (127.0.0.1:2080) so that blocked sites can be reached.

    Returns
    -------
    (domains, error)
        A sorted list of discovered domains and an optional error message.
    """
    # Normalise input
    domain = domain.strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]

    url = f"https://{domain}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
    }

    proxies = {"http": _LOCAL_PROXY, "https": _LOCAL_PROXY} if use_proxy else None

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
            proxies=proxies,
        )
        resp.raise_for_status()
    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            resp = requests.get(
                url, headers=headers, timeout=timeout,
                allow_redirects=True, verify=False,
                proxies=proxies,
            )
            resp.raise_for_status()
        except Exception as exc:
            return [], f"Ошибка загрузки: {exc}"
    except Exception as exc:
        return [], f"Ошибка загрузки: {exc}"

    # The final URL after redirects
    final_domain = _extract_domain(resp.url)

    content_type = resp.headers.get("Content-Type", "")
    if "html" not in content_type.lower() and "text" not in content_type.lower():
        return [domain], f"Ответ не HTML (Content-Type: {content_type})"

    html = resp.text

    # Parse main page
    extractor = _LinkExtractor(resp.url)
    try:
        extractor.feed(html)
    except Exception:
        pass

    all_domains = set(extractor.domains)
    if final_domain:
        all_domains.add(final_domain)
    all_domains.add(domain)

    # Optionally follow external CSS/JS for deeper discovery
    if follow_subresources:
        sub_urls: List[str] = []
        for d in list(all_domains):
            pass  # domains only, no full URLs stored

        # Re-scan HTML for full CSS/JS URLs to fetch
        css_js_re = re.compile(
            r"""(?:src|href)\s*=\s*["']((?:https?://|//)[^"']+\.(?:css|js)(?:\?[^"']*)?)["']""",
            re.IGNORECASE,
        )
        for m in css_js_re.finditer(html):
            sub_url = m.group(1)
            if sub_url.startswith("//"):
                sub_url = "https:" + sub_url
            sub_urls.append(sub_url)

        # Fetch up to 20 sub-resources
        for sub_url in sub_urls[:20]:
            try:
                sub_resp = requests.get(
                    sub_url, headers=headers, timeout=8,
                    allow_redirects=True, verify=False,
                    proxies=proxies,
                )
                if sub_resp.ok:
                    for m2 in _URL_RE.finditer(sub_resp.text):
                        d = m2.group(1).lower().rstrip(".")
                        if d and "." in d and d not in _IGNORE_DOMAINS:
                            all_domains.add(d)
                    for m2 in _CSS_URL_RE.finditer(sub_resp.text):
                        d = _extract_domain(m2.group(1))
                        if d:
                            all_domains.add(d)
            except Exception:
                continue

    # Clean up results
    all_domains.discard("")
    result = sorted(all_domains)
    return result, None


def discover_domains_async(
    domain: str,
    callback: Callable[[List[str], Optional[str]], None],
    *,
    timeout: int = 15,
    follow_subresources: bool = False,
    use_proxy: bool = False,
) -> threading.Thread:
    """Run discover_domains in a background thread.

    ``callback(domains, error)`` is called when done.
    Returns the thread object.
    """
    def _worker():
        domains, error = discover_domains(
            domain, timeout=timeout, follow_subresources=follow_subresources,
            use_proxy=use_proxy,
        )
        callback(domains, error)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t
