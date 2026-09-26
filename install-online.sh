#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker ist nicht installiert. Bitte Docker Engine + Compose installieren."
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose ist nicht verfügbar. Bitte Docker Compose installieren."
  exit 1
fi

read -r -p "Domain [app.emergency-delivery.de]: " DOMAIN
DOMAIN="${DOMAIN:-app.emergency-delivery.de}"

if [ -f .env ]; then
  echo ".env existiert bereits – vorhandene Zugangsdaten werden beibehalten."
else
  SECRET="$(openssl rand -hex 48 2>/dev/null || true)"
  if [ -z "$SECRET" ]; then
    SECRET="$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 96)"
  fi
  {
    echo "ED_DOMAIN=$DOMAIN"
    echo "JWT_SECRET=$SECRET"
  } > .env
  chmod 600 .env
fi

echo "Starte Emergency Delivery …"
docker compose up -d --build

echo
echo "Installation abgeschlossen."
echo "URL: https://$DOMAIN"
echo "Status: docker compose ps"
echo "Logs:   docker compose logs -f emergency-delivery"
