#!/usr/bin/env bash
# Create deploy/.env with fresh random secrets. Never overwrites an existing .env.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  echo ".env already exists, leaving it untouched."; exit 0
fi

read -r -p "Domain name (e.g. soc.example.uz), or press Enter to use the server IP over plain HTTP: " DOMAIN
if [ -n "$DOMAIN" ]; then
  SITE_ADDRESS="$DOMAIN"; PUBLIC_URL="https://$DOMAIN"
else
  IP="$(curl -fsS https://api.ipify.org || echo "SERVER_IP")"
  SITE_ADDRESS=":80"; PUBLIC_URL="http://$IP"
fi

umask 077
cat > .env <<ENV
SITE_ADDRESS=$SITE_ADDRESS
PUBLIC_URL=$PUBLIC_URL
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SENTINELX_API_KEY=$(openssl rand -hex 32)
SENTINELX_JWT_SECRET_KEY=$(openssl rand -hex 32)
# Optional: public key from the vendor (license_public.key). Leave empty to disable license enforcement.
SENTINELX_LICENSE_PUBLIC_KEY=
# Optional: enables AI analysis. Sends incident text to Google; leave empty for on-prem/bank installs.
SENTINELX_GEMINI_API_KEY=
ENV
echo "Created deploy/.env ($PUBLIC_URL). Keep this file private and back it up."
