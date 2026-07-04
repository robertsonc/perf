#!/usr/bin/env bash
# One-shot publish of the Network Vitals app to github.com/robertsonc/netvitals.
#
# Run from anywhere inside the perf repo, with git credentials that can push
# to netvitals:   bash scripts/publish_netvitals.sh
#
# Copies netquality/ (app, bats, assets, README) into a fresh clone of the
# netvitals repo and pushes to main. Idempotent: re-run any time netquality/
# changes in perf; the in-app updater (--update) picks the new version up
# from the raw URL immediately.
set -euo pipefail

REPO_URL="${NETVITALS_URL:-git@github.com:robertsonc/netvitals.git}"
SRC="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)/netquality"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Publishing $SRC -> $REPO_URL"
git clone --depth 1 "$REPO_URL" "$WORK/netvitals"
cd "$WORK/netvitals"

# Sync app content (keep the repo's .git; replace everything else)
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cp -r "$SRC"/. .
rm -f lastpeer.txt ./*.bak
cat > .gitignore <<'EOF'
__pycache__/
*.pyc
dist/
build/
*.spec
lastpeer.txt
*.bak
EOF

git add -A
if git diff --cached --quiet; then
    echo "Already up to date — nothing to publish."
    exit 0
fi
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' netquality.py)"
git commit -m "Publish Network Vitals ${VERSION:-unknown} from perf"
git push origin HEAD:main
echo "Done. Updater URL now serves ${VERSION:-unknown}:"
echo "  https://raw.githubusercontent.com/robertsonc/netvitals/main/netquality.py"
