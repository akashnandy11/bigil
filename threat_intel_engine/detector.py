"""Detect indicator type from user input."""

import re
from urllib.parse import urlparse

IPV4_RE = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')
SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')
MD5_RE = re.compile(r'^[a-fA-F0-9]{32}$')
DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def detect_indicator_type(value: str) -> str:
    """Return indicator type: ip, ipv6, url, domain, hash_sha256, hash_md5, unknown."""
    value = (value or '').strip()
    if not value:
        return 'unknown'

    if value.startswith(('http://', 'https://', 'ftp://')):
        return 'url'

    if IPV4_RE.match(value):
        return 'ip'

    if SHA256_RE.match(value):
        return 'hash_sha256'

    if MD5_RE.match(value):
        return 'hash_md5'

    if IPV6_RE.match(value) and ':' in value and len(value) > 6:
        return 'ipv6'

    if DOMAIN_RE.match(value) or ('.' in value and ' ' not in value and '/' not in value):
        return 'domain'

    return 'unknown'


def normalize_indicator(value: str, indicator_type: str) -> str:
    value = value.strip()
    if indicator_type == 'url':
        parsed = urlparse(value if '://' in value else f'http://{value}')
        if parsed.scheme in ('http', 'https'):
            return value if '://' in value else f'http://{value}'
    return value
