#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 || ! -s "$1" ]]; then echo 'usage: restore.sh EXISTING_BACKUP.db' >&2; exit 2; fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
compose=(docker compose --env-file "$script_dir/.env" -f "$script_dir/compose.yml")
"${compose[@]}" exec -T api sh -c 'cat > /state/restore.db' < "$1"
"${compose[@]}" stop api
if ! "${compose[@]}" run --rm --no-deps api logshield-api --restore; then
    "${compose[@]}" start api
    echo 'restore rejected; previous database was retained' >&2
    exit 1
fi
"${compose[@]}" up -d api
