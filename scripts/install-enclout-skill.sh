#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_NAME="enclout-openclaw-agent"
SRC="$ROOT_DIR/skills/$SKILL_NAME"
DEST_BASE="${1:-$HOME/.agents/skills}"
DEST="$DEST_BASE/$SKILL_NAME"

if [[ ! -d "$SRC" ]]; then
  echo "source skill not found: $SRC"
  exit 1
fi

mkdir -p "$DEST_BASE"
rm -rf "$DEST"
cp -R "$SRC" "$DEST"

echo "installed skill: $SKILL_NAME"
echo "destination: $DEST"
echo "restart the agent runtime to load the new skill"
