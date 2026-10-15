"""Pseudonymous source tags for the human-trials log.

We never store a visitor's IP address. Each /play row carries two keyed
hashes instead: `src` over the exact address and `net` over its network
(/24 for IPv4, /64 for IPv6). They let the operator cluster and purge a
spamming source without the log containing anything reversible — the key is
derived from the server secret, so no rainbow table applies, and rotating
the secret unlinks old rows for good.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress


def _network(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:  # "unknown", "testclient", unix sockets ...
        return ip
    bits = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


def source_tags(key: bytes, ip: str) -> tuple[str, str]:
    """(src, net): 16-hex-char HMAC-SHA256 tags of the address and its network."""
    def tag(label: str, value: str) -> str:
        return hmac.new(key, f"{label}:{value}".encode(), hashlib.sha256).hexdigest()[:16]

    return tag("src", ip), tag("net", _network(ip))
