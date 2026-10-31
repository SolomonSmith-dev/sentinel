#!/bin/sh
set -eu

case "${1:-}" in
  -*) ;;
  *) exec "$@" ;;
esac

chown -R sentinel:sentinel /var/log/suricata /var/lib/suricata /var/run/suricata
# AC-KS is the recommended software matcher when Hyperscan is unavailable.
exec suricata -c /etc/suricata/suricata.yaml --user sentinel --group sentinel \
  --set mpm-algo=ac-ks "$@"
