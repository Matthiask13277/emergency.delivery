#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

FILE="${1:-}"
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "Verwendung: ./restore-online.sh backups/emergency-data-YYYY-MM-DD_HH-MM-SS.tar.gz"
  exit 1
fi

docker compose down
# Restore only the application data volume. Caddy certificates/config remain untouched.
docker run --rm \
  -v "$(basename "$PWD")_emergency_data:/data" \
  -v "$PWD:/backup:ro" \
  alpine:3.20 sh -c 'rm -rf /data/* /data/.[!.]* /data/..?* 2>/dev/null || true; tar -xzf "/backup/'"$FILE"'" -C /data'

docker compose up -d
 echo "Restore abgeschlossen."
