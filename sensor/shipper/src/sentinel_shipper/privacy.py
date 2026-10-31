"""Privacy guard: the same scan the Worker runs on every ingest body (docs/api.md).

Run on the exact serialized bytes about to be sent. A match means a bug
somewhere upstream let an address through; we refuse to send and quarantine.
"""

from __future__ import annotations

import re

# Ported verbatim from the Worker (api/src/ingest.ts) so both sides classify every string the
# same way. Digits are spelled [0-9] because JS \d is ASCII-only while Python's is Unicode.
# Shared test vectors: api/test/pii-vectors.json (run by pytest and vitest).
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
MAC = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}(?![0-9a-fA-F])")
IPV6 = re.compile(
    "|".join(
        [
            r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])",
            r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?(?![0-9a-fA-F])",
            r"(?<![0-9a-fA-F:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-fA-F])",
        ]
    )
)

HOSTNAME = re.compile(
    r"(?<![a-zA-Z0-9_-])(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
    r"(?:local|lan|home|internal|localhost|home\.arpa)(?![a-zA-Z0-9_-])",
    re.IGNORECASE | re.ASCII,
)

PATTERNS: dict[str, re.Pattern[str]] = {"ipv4": IPV4, "mac": MAC, "ipv6": IPV6, "hostname": HOSTNAME}


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
    # Repeat until stable: removing one match can expose another (e.g. "1.2.3.4.5.6.7.8").
    for _ in range(8):
        before = text
        for pattern in (MAC, IPV6, IPV4, HOSTNAME):
            text = pattern.sub("[redacted]", text)
        if text == before:
            break
    return text
