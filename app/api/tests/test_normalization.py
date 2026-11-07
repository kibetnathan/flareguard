from __future__ import annotations

import pytest

from services.normalization import URLValidationError, hash_url, normalize_url


def test_valid_http_and_https():
    https = normalize_url("https://example.com/login")
    assert https.scheme == "https"
    assert https.hostname == "example.com"
    assert https.registrable_domain == "example.com"
    assert https.is_https is True

    http = normalize_url("http://example.com/")
    assert http.scheme == "http"
    assert http.is_https is False


def test_hostname_is_lowercased_and_trailing_dot_stripped():
    target = normalize_url("https://Mail.Example.COM./inbox")
    assert target.hostname == "mail.example.com"
    assert target.registrable_domain == "example.com"


def test_ip_address_urls():
    v4 = normalize_url("http://192.168.0.10/admin")
    assert v4.is_ip is True
    assert v4.registrable_domain == "192.168.0.10"

    v6 = normalize_url("http://[2001:db8::1]:8080/")
    assert v6.is_ip is True
    assert v6.port == 8080


def test_punycode_and_idn():
    target = normalize_url("https://пример.рф/login")
    assert target.is_punycode is True
    assert target.hostname.startswith("xn--")
    assert target.hostname_unicode == "пример.рф"


def test_multiple_subdomains():
    target = normalize_url("https://a.b.c.example.co.uk/path")
    assert target.registrable_domain == "example.co.uk"
    assert target.subdomain_count == 3


def test_redacted_drops_query_and_fragment():
    target = normalize_url("https://example.com/reset?token=SECRET#frag")
    assert target.redacted() == "https://example.com/reset"
    assert "SECRET" not in target.redacted()


def test_hash_is_stable_and_query_sensitive():
    a = normalize_url("https://example.com/a?x=1")
    b = normalize_url("https://example.com/a?x=2")
    assert hash_url(a.normalized_url) == hash_url(a.normalized_url)
    assert hash_url(a.normalized_url) != hash_url(b.normalized_url)


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://",
        "",
        "   ",
        "https://exa mple.com/",
        "https://foo_bar.com/",
        "https://example.com/%",
        "https://example.com/%zz",
    ],
)
def test_invalid_urls_are_rejected(url):
    with pytest.raises(URLValidationError):
        normalize_url(url)


@pytest.mark.parametrize(
    "url",
    ["ftp://example.com", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd"],
)
def test_unsupported_schemes_are_rejected(url):
    with pytest.raises(URLValidationError):
        normalize_url(url)


@pytest.mark.parametrize("url", ["https://user:pass@example.com/", "https://user@example.com/"])
def test_urls_with_credentials_are_rejected(url):
    with pytest.raises(URLValidationError):
        normalize_url(url)


def test_url_over_max_length_is_rejected():
    with pytest.raises(URLValidationError):
        normalize_url("https://example.com/" + "a" * 3000, max_length=2048)
