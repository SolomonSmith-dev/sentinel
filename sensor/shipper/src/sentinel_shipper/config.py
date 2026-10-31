"""Configuration from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping


class ConfigError(ValueError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Settings:
    api: str
    token: str = field(repr=False)
    salt: str = field(repr=False)
    sensor_id: str = "sensor-01"
    windows_dir: Path = Path("/var/lib/sentinel/windows")
    state_dir: Path = Path("/var/lib/sentinel/state")
    eve_path: Path = Path("/var/log/suricata/eve.json")
    wan_ip: str | None = field(default=None, repr=False)
    geo_db: Path = Path("/usr/share/sentinel/ip2country-v4.tsv")
    oui_db: Path = Path("/usr/share/sentinel/oui.csv")
    interval_s: float = 30.0
    retrain_at: str = "03:30"
    http_timeout_s: float = 10.0

    @property
    def ingest_url(self) -> str:
        base = self.api.rstrip("/")
        return base if base.endswith("/api/ingest") else base + "/api/ingest"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        e = os.environ if env is None else env

        def get(name: str, default: str | None = None) -> str | None:
            value = e.get(name)
            if value is None or value.strip() == "":
                return default
            return value.strip()

        def secret(name: str) -> str | None:
            value, filename = get(name), get(name + "_FILE")
            if value and filename:
                raise ConfigError(f"set only one of {name} and {name}_FILE")
            if filename:
                try:
                    return Path(filename).read_text(encoding="utf-8").strip() or None
                except (OSError, UnicodeError):
                    raise ConfigError(f"cannot read {name}_FILE") from None
            return value

        token = secret("SENTINEL_TOKEN")
        salt = secret("SENTINEL_SALT")
        missing = [n for n, v in (("SENTINEL_TOKEN", token), ("SENTINEL_SALT", salt)) if not v]
        if missing:
            raise ConfigError(
                f"refusing to start: {', '.join(missing)} not set. "
                "The token authenticates ingest and the salt anonymizes MAC addresses; "
                "both are required."
            )
        api = get("SENTINEL_API", "https://sentinel.solomonsmith.dev")
        assert api is not None and token is not None and salt is not None
        if not api.startswith(("https://", "http://")):
            raise ConfigError("SENTINEL_API must be an http(s) URL")
        retrain_at = get("SENTINEL_RETRAIN_AT", "03:30") or "03:30"
        _parse_hhmm(retrain_at)
        return cls(
            api=api,
            token=token,
            salt=salt,
            sensor_id=get("SENTINEL_SENSOR_ID", "sensor-01") or "sensor-01",
            windows_dir=Path(get("SENTINEL_WINDOWS_DIR", "/var/lib/sentinel/windows") or ""),
            state_dir=Path(get("SENTINEL_STATE_DIR", "/var/lib/sentinel/state") or ""),
            eve_path=Path(get("SENTINEL_EVE", "/var/log/suricata/eve.json") or ""),
            wan_ip=get("SENTINEL_WAN_IP"),
            geo_db=Path(get("SENTINEL_GEO_DB", "/usr/share/sentinel/ip2country-v4.tsv") or ""),
            oui_db=Path(get("SENTINEL_OUI_DB", "/usr/share/sentinel/oui.csv") or ""),
            interval_s=float(get("SENTINEL_INTERVAL_S", "30") or 30),
            retrain_at=retrain_at,
        )


def _parse_hhmm(value: str) -> tuple[int, int]:
    try:
        hh, mm = value.split(":")
        h, m = int(hh), int(mm)
    except ValueError as exc:
        raise ConfigError(f"bad HH:MM time {value!r}") from exc
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ConfigError(f"bad HH:MM time {value!r}")
    return h, m


parse_hhmm = _parse_hhmm
