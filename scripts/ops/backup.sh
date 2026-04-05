#!/usr/bin/env bash
set -euo pipefail

# Backup named volumes used by Stellarae services.
# Override defaults with environment variables if your compose project name differs.

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="${BACKUP_ROOT:-$PWD/backups}"
BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"

STAFFDB_VOLUME="${STAFFDB_VOLUME:-stellaraesecure_staffdb-data}"
OAUTH2_VOLUME="${OAUTH2_VOLUME:-stellaraesecure_oauth2-data}"
TWOFA_VOLUME="${TWOFA_VOLUME:-stellaraesecure_twofa-data}"

mkdir -p "$BACKUP_DIR"

echo "Creating backups in: $BACKUP_DIR"

backup_volume() {
  local volume_name="$1"
  local output_name="$2"

  echo "Backing up volume: $volume_name"
  docker run --rm \
    -v "$volume_name:/from:ro" \
    -v "$BACKUP_DIR:/to" \
    alpine:3.20 \
    sh -c "cd /from && tar -czf /to/${output_name}.tar.gz ."
}

backup_volume "$STAFFDB_VOLUME" "staffdb-data"
backup_volume "$OAUTH2_VOLUME" "oauth2-data"
backup_volume "$TWOFA_VOLUME" "twofa-data"

echo "Backup completed successfully."
