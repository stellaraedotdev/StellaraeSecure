#!/usr/bin/env bash
set -euo pipefail

# Restore named volumes from backup archives produced by scripts/ops/backup.sh.

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <backup-directory>"
  echo "Example: $0 ./backups/20260405-120000"
  exit 1
fi

BACKUP_DIR="$1"
if [[ ! -d "$BACKUP_DIR" ]]; then
  echo "Backup directory does not exist: $BACKUP_DIR"
  exit 1
fi

STAFFDB_VOLUME="${STAFFDB_VOLUME:-stellaraesecure_staffdb-data}"
OAUTH2_VOLUME="${OAUTH2_VOLUME:-stellaraesecure_oauth2-data}"
TWOFA_VOLUME="${TWOFA_VOLUME:-stellaraesecure_twofa-data}"

restore_volume() {
  local volume_name="$1"
  local archive_name="$2"
  local archive_path="$BACKUP_DIR/${archive_name}.tar.gz"

  if [[ ! -f "$archive_path" ]]; then
    echo "Missing archive: $archive_path"
    exit 1
  fi

  echo "Restoring volume: $volume_name"
  docker run --rm \
    -v "$volume_name:/to" \
    -v "$BACKUP_DIR:/from:ro" \
    alpine:3.20 \
    sh -c "rm -rf /to/* /to/.[!.]* /to/..?* 2>/dev/null || true; tar -xzf /from/${archive_name}.tar.gz -C /to"
}

restore_volume "$STAFFDB_VOLUME" "staffdb-data"
restore_volume "$OAUTH2_VOLUME" "oauth2-data"
restore_volume "$TWOFA_VOLUME" "twofa-data"

echo "Restore completed successfully."
