#!/usr/bin/env bash
# backup.sh — Snapshot the trak SQLite database.
#
# Uses SQLite's online backup API (atomic, doesn't block the running daemon).
# Compresses with zstd. Rotates: keeps daily snapshots for 30d, monthly for 12mo.
#
# Usage:
#   ./backup.sh                    # one-shot snapshot
#   ./backup.sh --rotate           # snapshot + prune old files
#
# Schedule via launchd (macOS) or cron (Linux). See `Trak database backups` doc.

set -euo pipefail

DB_PATH="${TRAK_DB:-${HOME}/Library/Application Support/trak/trak.db}"
[[ ! -f "$DB_PATH" ]] && DB_PATH="${HOME}/.local/share/trak/trak.db"
[[ ! -f "$DB_PATH" ]] && { echo "ERROR: trak.db not found. Set TRAK_DB." >&2; exit 1; }

BACKUP_DIR="${TRAK_BACKUP_DIR:-${HOME}/.trak-backups}"
FALLBACK_DIR="${HOME}/.trak-backups"

# Guard: if the backup dir is on a /Volumes/ mount, verify the volume is mounted.
# macOS auto-creates /Volumes/<name> on mount and removes it on unmount, so
# `[[ -d ]]` is reliable for /Volumes/* paths.
if [[ "$BACKUP_DIR" == /Volumes/* ]]; then
    # Extract /Volumes/<name> (the mountpoint, regardless of subpath)
    volume_mount=$(echo "$BACKUP_DIR" | awk -F/ '{print "/" $2 "/" $3}')
    if [[ ! -d "$volume_mount" ]]; then
        echo "WARN: $volume_mount not mounted — falling back to $FALLBACK_DIR" >&2
        BACKUP_DIR="$FALLBACK_DIR"
    fi
fi

mkdir -p "$BACKUP_DIR"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
target="$BACKUP_DIR/trak-$stamp.db"

# Online backup — atomic snapshot via SQLite's backup API.
# Works while the daemon is running. Doesn't lock writers.
sqlite3 "$DB_PATH" ".backup '$target'"

# Compress with zstd (faster + better ratio than gzip)
if command -v zstd >/dev/null; then
    zstd --rm -q -19 "$target"
    target="$target.zst"
fi

size=$(du -h "$target" | cut -f1)
echo "snapshot: $target ($size)"

# Rotation
if [[ "${1:-}" == "--rotate" ]]; then
    # Keep all from last 30 days
    # Keep one per month from older
    cd "$BACKUP_DIR"

    # Build a list of files we're keeping
    keep=$(mktemp)
    trap "rm -f '$keep'" EXIT

    # Last 30 days: keep all
    find . -maxdepth 1 -name 'trak-*.db*' -mtime -30 -print >> "$keep"

    # Older than 30 days: keep one per month (the first of each month)
    find . -maxdepth 1 -name 'trak-*.db*' -mtime +30 -print | \
        sort | \
        awk -F'trak-' '{ split($2, a, "T"); month = substr(a[1], 1, 6); if (month != prev) { print $0; prev = month } }' >> "$keep"

    # Delete everything not in the keep list
    deleted=0
    for f in trak-*.db*; do
        if ! grep -qxF "./$f" "$keep"; then
            rm -- "$f"
            deleted=$((deleted + 1))
        fi
    done
    [[ $deleted -gt 0 ]] && echo "rotated: removed $deleted old snapshots"
fi
