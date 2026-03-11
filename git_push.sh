#!/usr/bin/env bash
# git_push.sh — Push to GitHub with PAT
# Chạy: bash git_push.sh YOUR_NEW_TOKEN

set -euo pipefail
TOKEN="${1:-}"
[[ -z "${TOKEN}" ]] && { echo "Usage: bash git_push.sh YOUR_PAT_TOKEN"; exit 1; }

cd ~/C2plus

# Xóa .bak files
find . -name "*.bak*" -delete
git rm --cached $(git ls-files "*.bak*") 2>/dev/null || true
git add -A

# Amend commit nếu có staged changes
if ! git diff --cached --quiet; then
    git commit --amend --no-edit
fi

# Set remote URL với token
git remote set-url origin "https://dainghiavn:${TOKEN}@github.com/dainghiavn/C2plus.git"

# Push
git push origin main

# Xóa token khỏi remote URL sau khi push xong
git remote set-url origin "https://github.com/dainghiavn/C2plus.git"

echo "✔ Done — token cleared from remote URL"
