#!/bin/bash
# ContrastAPI deploy script
# Usage: ssh local 'bash /tmp/deploy-api.sh'

set -e

APP_DIR="/opt/contrastapi"
SERVICE="contrastapi"

echo "=== Deploying $SERVICE ==="

cd "$APP_DIR"

# Discard local changes and remove untracked files in static/fonts
git checkout -- .
git clean -fd app/static/fonts/

# Pull latest
git pull

# Restart service
systemctl restart "$SERVICE"

# Warm up workers
sleep 2
curl -s http://127.0.0.1:8002/v1/status > /dev/null && echo "Workers warmed up"

echo "=== $SERVICE deployed ==="
echo "Version: $(grep VERSION app/config.py 2>/dev/null || echo 'n/a')"
