#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then echo 'usage: backup.sh OUTPUT.db' >&2; exit 2; fi
if [[ -e "$1" ]]; then echo 'backup destination already exists' >&2; exit 2; fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
compose=(docker compose --env-file "$script_dir/.env" -f "$script_dir/compose.yml")
umask 077
"${compose[@]}" exec -T api logshield-api --backup
"${compose[@]}" exec -T api cat /state/logshield-backup.db > "$1"
test -s "$1"
