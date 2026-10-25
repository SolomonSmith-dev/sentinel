#!/usr/bin/env bash
# Deploy the Sentinel sensor stack (suricata, sentinel-capture, sentinel-shipper)
# on the Debian sensor host. Run from the repo root on that host.
#
#   ./deploy-sensor.sh            build and start
#   ./deploy-sensor.sh --dry-run  validate config, change nothing
#
# Token: set SENTINEL_TOKEN in .env, or export it, or put it in
# ~/.config/sentinel/token (one line, mode 600). The salt is generated here
# once and never leaves this host.
set -euo pipefail

cd "$(dirname "$0")"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

COMPOSE_FILE="sensor/docker-compose.yml"
ENV_FILE=".env"
TOKEN_FILE="${HOME}/.config/sentinel/token"

log() { printf '[deploy] %s\n' "$*"; }
die() { printf '[deploy] ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not installed"
docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"
command -v openssl >/dev/null || die "openssl not installed"
[[ -f "$COMPOSE_FILE" ]] || die "$COMPOSE_FILE not found; run from the repo root"

# Read KEY's value from .env without sourcing it.
env_get() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

# Set KEY=VALUE in .env, replacing an existing line. Never echoes the value.
env_set() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$value" >> "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

if [[ ! -f "$ENV_FILE" ]]; then
  if (( DRY_RUN )); then
    log "would create $ENV_FILE from .env.example"
    ENV_FILE=".env.example"
  else
    (umask 077; cp .env.example "$ENV_FILE")
    log "created $ENV_FILE from .env.example"
  fi
fi

if (( ! DRY_RUN )); then
  chmod 600 "$ENV_FILE"

  if [[ -z "$(env_get SENTINEL_SALT)" ]]; then
    env_set SENTINEL_SALT "$(openssl rand -hex 32)"
    log "generated SENTINEL_SALT"
  fi

  if [[ -z "$(env_get SENTINEL_TOKEN)" ]]; then
    if [[ -n "${SENTINEL_TOKEN:-}" ]]; then
      env_set SENTINEL_TOKEN "$SENTINEL_TOKEN"
    elif [[ -s "$TOKEN_FILE" ]]; then
      env_set SENTINEL_TOKEN "$(head -n 1 "$TOKEN_FILE")"
    else
      die "SENTINEL_TOKEN missing: put it in $TOKEN_FILE or $ENV_FILE"
    fi
    log "set SENTINEL_TOKEN"
  fi

  if [[ -z "$(env_get SENTINEL_IFACE)" || "$(env_get SENTINEL_IFACE)" == "eth0" ]]; then
    iface="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
    [[ -n "$iface" ]] || die "could not detect the default interface; set SENTINEL_IFACE in $ENV_FILE"
    env_set SENTINEL_IFACE "$iface"
    log "SENTINEL_IFACE=$iface"
  fi
fi

iface="$(env_get SENTINEL_IFACE)"
if [[ -n "$iface" ]] && ! ip link show "$iface" >/dev/null 2>&1; then
  if (( DRY_RUN )); then
    log "interface $iface not present on this host (ok for a dry run)"
  else
    die "interface $iface does not exist"
  fi
fi

log "validating compose file"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config --quiet

if (( DRY_RUN )); then
  log "dry run ok; nothing started"
  exit 0
fi

log "building images (first build downloads geo and OUI data)"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build

log "starting stack"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

sleep 5
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
log "done. Follow the shipper with:"
log "  docker compose -f $COMPOSE_FILE logs -f sentinel-shipper"
log "First batch ships within about 60 seconds."
