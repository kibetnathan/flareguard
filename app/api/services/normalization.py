from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import idna
from publicsuffixlist import PublicSuffixList

_PSL = PublicSuffixList()

_ALLOWED_SCHEMES = {"http", "https"}
# Any whitespace or control character is not valid inside a URL.
_ILLEGAL_CHARS = re.compile(r"[\x00-\x20\x7f]")
# A percent sign that is not followed by two hex digits is malformed encoding.
_MALFORMED_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
# ASCII hostnames: alphanumeric labels separated by dots (hyphens inside a label).
_ASCII_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


class URLValidationError(ValueError):
    """Raised when a submitted URL cannot be safely analyzed."""


@dataclass(frozen=True)
class URLTarget:
    """Normalized view of a submitted URL.

    ``original_url`` is kept only in memory for the duration of a request and is
    never persisted; ``redacted()`` is used for logging and storage.
    """

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    hostname_unicode: str
    registrable_domain: str | None
    is_ip: bool
    is_punycode: bool
    path: str
    query: str
    port: int | None

    @property
    def labels(self) -> list[str]:
        return [label for label in self.hostname.split(".") if label]

    @property
    def subdomain_count(self) -> int:
        if self.is_ip or not self.registrable_domain:
            return 0
        registrable_labels = len(self.registrable_domain.split("."))
        return max(0, len(self.labels) - registrable_labels)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def has_query(self) -> bool:
        return bool(self.query)

    def redacted(self) -> str:
        """Scheme + host + path only — drops query and fragment."""
        host = self.hostname
        if self.is_ip and ":" in host:
            host = f"[{host}]"
        netloc = f"{host}:{self.port}" if self.port else host
        return urlunsplit((self.scheme, netloc, self.path, "", ""))


def hash_url(normalized_url: str) -> str:
    """Stable sha256 of a normalized URL, used as a non-sensitive cache key."""
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def _registrable_domain(hostname: str) -> str | None:
    suffix = _PSL.privatesuffix(hostname)
    if suffix:
        return suffix
    labels = [label for label in hostname.split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return hostname or None


def normalize_url(raw_url: str, *, max_length: int = 2048) -> URLTarget:
    if not isinstance(raw_url, str):
        raise URLValidationError("url must be a string")

    url = raw_url.strip()
    if not url:
        raise URLValidationError("url must not be empty")
    if len(url) > max_length:
        raise URLValidationError("url exceeds the maximum allowed length")
    if _ILLEGAL_CHARS.search(url):
        raise URLValidationError("url contains whitespace or control characters")
    if _MALFORMED_PERCENT.search(url):
        raise URLValidationError("url contains malformed percent-encoding")

    try:
        parsed = urlsplit(url)
    except ValueError as exc:  # pragma: no cover - urlsplit rarely raises
        raise URLValidationError("url could not be parsed") from exc

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise URLValidationError("only http and https URLs are supported")

    if not parsed.netloc:
        raise URLValidationError("url must include a host")

    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("urls with embedded credentials are not supported")

    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise URLValidationError("url must include a hostname")

    try:
        port = parsed.port
    except ValueError as exc:
        raise URLValidationError("url contains an invalid port") from exc

    path = parsed.path or "/"
    query = parsed.query

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        ip_address = None

    if ip_address is not None:
        ascii_host = str(ip_address)
        hostname_unicode = ascii_host
        is_punycode = False
        is_ip = True
        registrable: str | None = ascii_host
    else:
        is_ip = False
        try:
            ascii_host = idna.encode(hostname).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise URLValidationError("hostname is not a valid domain name") from exc
        if not _ASCII_HOST_RE.match(ascii_host):
            raise URLValidationError("hostname contains invalid characters")
        is_punycode = any(label.startswith("xn--") for label in ascii_host.split("."))
        try:
            hostname_unicode = idna.decode(ascii_host)
        except (idna.IDNAError, UnicodeError):
            hostname_unicode = hostname
        registrable = _registrable_domain(ascii_host)

    netloc = f"[{ascii_host}]" if is_ip and ":" in ascii_host else ascii_host
    if port:
        netloc = f"{netloc}:{port}"
    normalized_url = urlunsplit((scheme, netloc, path, query, ""))

    return URLTarget(
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=ascii_host,
        hostname_unicode=hostname_unicode,
        registrable_domain=registrable,
        is_ip=is_ip,
        is_punycode=is_punycode,
        path=path,
        query=query,
        port=port,
    )
