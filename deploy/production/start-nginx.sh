#!/bin/sh
set -eu
printf '%s' "${LOGSHIELD_VIEWER_TOKEN:?}" | grep -Eq '^[a-f0-9]{64}$'
envsubst '${LOGSHIELD_VIEWER_TOKEN}' </etc/nginx/nginx.conf.template >/tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
