#!/bin/sh
# Entrypoint for the Followee demonstration handle authority container.
#
# - binds the production `followee handle serve` to 0.0.0.0:$PORT
#   (Railway injects PORT; 8080 is the local fallback);
# - derives the advertised public base URI from explicit operator
#   configuration (FOLLOWEE_BASE_URI) or from Railway's assigned public
#   domain (RAILWAY_PUBLIC_DOMAIN). Both are deployment configuration,
#   never request headers: no Host/X-Forwarded-* value can influence the
#   served links;
# - `exec` replaces the shell so the authority is PID 1 and receives
#   Railway's SIGTERM directly for a clean shutdown;
# - prints nothing itself: the one startup object comes from the
#   authority and contains only public configuration facts.
set -eu

PORT="${PORT:-8080}"
CONFIG="${FOLLOWEE_CONFIG:-/app/authority.json}"

if [ -n "${FOLLOWEE_BASE_URI:-}" ]; then
    BASE="${FOLLOWEE_BASE_URI}"
elif [ -n "${RAILWAY_PUBLIC_DOMAIN:-}" ]; then
    BASE="https://${RAILWAY_PUBLIC_DOMAIN}/"
else
    echo "set FOLLOWEE_BASE_URI (https://…/) or deploy where RAILWAY_PUBLIC_DOMAIN is provided" >&2
    exit 1
fi

exec followee handle serve \
    --config "${CONFIG}" \
    --listen "0.0.0.0:${PORT}" \
    --base-uri "${BASE}"
