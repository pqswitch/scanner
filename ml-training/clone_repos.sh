#!/usr/bin/env bash
# clone_repos.sh  –  Clone every repo listed in repos.csv into THIS_FOLDER/repos
# Usage:  bash clone_repos.sh

set -euo pipefail
IFS=';'                                  # read CSV fields split by semicolon

CSV_FILE="repos.csv"
DEST_DIR="./repos"

# Make destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Skip the header, then process each subsequent line
tail -n +2 "$CSV_FILE" | while read -r REPO_NAME REPO_URL LANGUAGE STARS DESCRIPTION || true; do
  # Skip empty lines or lines with insufficient fields
  if [[ -z "${REPO_NAME:-}" ]] || [[ -z "${REPO_URL:-}" ]]; then
    echo "⚠️  Skipping invalid line: $REPO_NAME;$REPO_URL;$LANGUAGE;$STARS;$DESCRIPTION"
    continue
  fi

  # Trim possible surrounding quotes/spaces and remove trailing % if present
  REPO_NAME="${REPO_NAME//\"/}"
  REPO_NAME="${REPO_NAME%\%}"  # Remove trailing % if present
  REPO_URL="${REPO_URL//\"/}"

  # Local folder name = last path component of repo URL
  LOCAL_DIR="$DEST_DIR/$(basename "$REPO_URL" .git)"

  if [[ -d "$LOCAL_DIR/.git" ]]; then
    echo "✔ Already cloned: $REPO_NAME"
    continue
  fi

  echo "→ Cloning $REPO_NAME to $LOCAL_DIR"
  git clone --depth 1 "$REPO_URL" "$LOCAL_DIR" || {
    echo "✗ Failed to clone $REPO_NAME" >&2
  }
done

echo "✅ Repository cloning completed!" 