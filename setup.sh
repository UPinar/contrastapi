#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== ContrastAPI Setup ==="

# Python venv
echo "[1/4] Creating Python venv..."
cd "$SCRIPT_DIR"
python3 -m venv venv
venv/bin/pip install --quiet -r requirements.txt

# Database directory
echo "[2/4] Setting up database directory..."
mkdir -p /var/lib/contrastcyber
chmod 755 /var/lib/contrastcyber

# Systemd service
echo "[3/4] Installing systemd service..."
cp "$SCRIPT_DIR/deploy/systemd/contrastapi.service" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

# Start
echo "[4/4] Starting service..."
systemctl enable contrastapi
systemctl restart contrastapi
echo "=== Done! ==="
systemctl status contrastapi --no-pager | head -5
