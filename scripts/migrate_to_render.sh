#!/usr/bin/env bash
# =============================================================================
# NETOPS Database Migration Script: Oracle Cloud / Local -> Render PostgreSQL
# =============================================================================
set -e

echo "=== NETOPS Database Migration Helper ==="
echo ""

if [ -z "$1" ]; then
  echo "Usage: $0 <RENDER_EXTERNAL_DATABASE_URL>"
  echo ""
  echo "Example:"
  echo "  $0 'postgresql://netops:password@dpg-xxxx-a.frankfurt-postgres.render.com/netops'"
  echo ""
  echo "Get your External Database URL from Render Dashboard -> netops-db -> Connections -> External Database URL"
  exit 1
fi

TARGET_URL="$1"
BACKUP_FILE="netops_cloud_migration_$(date +%Y%m%d_%H%M%S).sql"

echo "[1/3] Creating local/current PostgreSQL database dump..."
if command -v pg_dump >/dev/null 2>&1; then
  # Try local netops database
  PGPASSWORD="netops_db_user" pg_dump -U netops_db_user -h localhost -p 5432 -d netops --no-owner --no-privileges -F p -f "$BACKUP_FILE" || \
  sudo -u postgres pg_dump -d netops --no-owner --no-privileges -F p -f "$BACKUP_FILE"
  echo "Dump saved to $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
else
  echo "[!] Error: pg_dump utility not found. Please install postgresql-client."
  exit 1
fi

echo ""
echo "[2/3] Verifying target Render PostgreSQL connection..."
psql "$TARGET_URL" -c "SELECT version();" >/dev/null 2>&1 || {
  echo "[!] Failed to connect to Render PostgreSQL. Please check your connection URL and internet access."
  exit 1
}
echo "Render PostgreSQL connection confirmed!"

echo ""
echo "[3/3] Restoring data into Render PostgreSQL..."
psql "$TARGET_URL" < "$BACKUP_FILE"

echo ""
echo "=== Migration Complete! ==="
echo "All accounts, devices, access schedules, and logs successfully imported into Render."
echo "Backup file preserved at: $(pwd)/$BACKUP_FILE"
