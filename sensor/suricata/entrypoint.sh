#!/bin/sh
set -eu

case "${1:-}" in
  -*) ;;
  *) exec "$@" ;;
esac

chown -R sentinel:sentinel /var/log/suricata /var/lib/suricata /var/run/suricata
# Explicit AC matching avoids Hyperscan CPU requirements on the older sensor.
exec suricata -c /etc/suricata/suricata.yaml --user sentinel --group sentinel \
  --set mpm-algo=ac "$@"
