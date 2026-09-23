#!/usr/bin/env bash
# Starts WordPress Playground with this plugin mounted, runs the PKCE e2e
# checks against it over HTTP, then stops the server.
#
# Needs Node.js (for npx) and Python 3. No Python packages are required.
set -euo pipefail

cd "$(dirname "$0")/../.."
PORT="${E2E_PORT:-9400}"
BASE="http://127.0.0.1:${PORT}"
LOG="$(mktemp)"

npx -y @wp-playground/cli@latest server \
	--port="$PORT" \
	--mount="$PWD:/wordpress/wp-content/plugins/oauth2" \
	--blueprint=tests/e2e/blueprint.json \
	>"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

echo "Waiting for Playground on $BASE ..."
ready=0
for _ in $(seq 1 150); do
	# Playground answers requests before it has finished booting, so wait for
	# its "Ready!" line as well as the file the blueprint writes.
	if grep -q 'Ready!' "$LOG" && curl -sf "$BASE/e2e-clients.json" >/dev/null; then
		ready=1
		break
	fi
	if ! kill -0 "$SERVER_PID" 2>/dev/null; then
		break
	fi
	sleep 2
done

if [ "$ready" != 1 ]; then
	cat "$LOG"
	echo "Playground did not become ready." >&2
	exit 1
fi

E2E_BASE_URL="$BASE" python3 tests/e2e/pkce.py
