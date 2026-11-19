#!/usr/bin/env bash
# Dump the PostgreSQL database to deploy/backups/ and keep the 14 newest files.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p backups
FILE="backups/sanitialx-$(date +%Y%m%d-%H%M%S).sql.gz"
docker compose -f docker-compose.prod.yml exec -T postgres pg_dump -U sentinelx sentinelx | gzip > "$FILE"
ls -1t backups/*.sql.gz | tail -n +15 | xargs -r rm --
echo "Backup written: $FILE"
