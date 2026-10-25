"""Privacy guard: the same scan the Worker runs on every ingest body (docs/api.md).

Run on the exact serialized bytes about to be sent. A match means a bug
somewhere upstream let an address through; we refuse to send and quarantine.
"""

from __future__ import annotations

import re

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}\b")
# "IPv6-looking": three or more colon-separated hex groups, or anything with "::".
# Our JSON is compact (separators ",", ":"), so a key/value pair never produces
# two colons separated only by hex digits.
IPV6 = re.compile(
    r"(?<![0-9A-Za-z_:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![0-9A-Za-z_:])"
    r"|(?<![0-9A-Za-z_:])(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?(?![0-9A-Za-z_])"
)

PATTERNS: dict[str, re.Pattern[str]] = {"ipv4": IPV4, "mac": MAC, "ipv6": IPV6}


class PrivacyViolation(Exception):
    def __init__(self, kinds: list[str]) -> None:
        super().__init__("privacy guard matched: " + ", ".join(kinds))
        self.kinds = kinds


def violations(text: str, wan_ip: str | None = None) -> list[str]:
    """Names of the patterns that match. Never returns the matched text."""
    found = [name for name, pattern in PATTERNS.items() if pattern.search(text)]
    if wan_ip and wan_ip in text:
        found.append("wan_ip")
    return found


def check(body: bytes | str, wan_ip: str | None = None) -> None:
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    found = violations(text, wan_ip)
    if found:
        raise PrivacyViolation(found)


def redact(text: str) -> str:
    """Scrub address-looking substrings from free text (e.g. Suricata signatures)."""
    for pattern in (MAC, IPV6, IPV4):
        text = pattern.sub("[redacted]", text)
    return text
