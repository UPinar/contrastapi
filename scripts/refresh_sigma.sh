#!/usr/bin/env bash
# Sparse-clone or update SigmaHQ detection rules into the directory passed as $1.
# Invoked by app/sigma/sync.py and (in production) by cron at 02:00 UTC daily.
set -euo pipefail

TARGET="${1:?usage: refresh_sigma.sh <target_dir>}"
REPO="https://github.com/SigmaHQ/sigma.git"
SUBDIRS=("rules" "rules-compliance" "rules-dfir" "rules-threat-hunting")

cd "$TARGET"

if [[ ! -d .git ]]; then
    git init -q
    git remote add origin "$REPO"
    git config core.sparseCheckout true
    git config core.sparseCheckoutCone true
fi

git sparse-checkout set "${SUBDIRS[@]}"
git fetch --depth 1 origin master
git reset --hard origin/master >/dev/null

echo "sigma corpus refreshed at $TARGET"
