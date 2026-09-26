#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backups
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
FILE="backups/emergency-data-$STAMP.tar.gz"

docker run --rm \
  -v "$(basename "$PWD")_emergency_data:/data:ro" \
  -v "$PWD/backups:/backup" \
  alpine:3.20 \
  tar -czf "/backup/$(basename "$FILE")" -C /data .

echo "Backup erstellt: $FILE"
