#!/usr/bin/env bash
# FisionTV+ release-train status across all four repos and the lab STB.
# Run from anywhere — paths are resolved relative to this script's location.
#
# Usage: ./scripts/status.sh
#
# Reports:
#   - per-repo: current branch, HEAD tag, working tree cleanliness, commits
#     ahead/behind origin, latest CI conclusion on main
#   - cross-repo: contract pin in backend vs android (must match), and
#     whether they're caught up to the latest contract tag
#   - open PRs across all four repos (via gh)
#   - lab STB: installed versionCode/Name vs active manifest's

set -uo pipefail

# Resolve repo locations from this script's path. Backend hosts the script,
# the other three are siblings under ~/Development/ (or wherever the user
# checked them out).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV_DIR="$(cd "$BACKEND/.." && pwd)"
ANDROID="$DEV_DIR/NetworkQualityHWC"
DASHBOARD="$DEV_DIR/NetworkQualityHWCDashboard"
CONTRACT="$DEV_DIR/fisiontv-cert-contract"

# Colors (TTY-only; degrades to plain text when piped)
if [ -t 1 ]; then
  C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_DIM= C_RED= C_GRN= C_YEL= C_BLU= C_BLD= C_RST=
fi

ok="${C_GRN}✓${C_RST}"
warn="${C_YEL}⚠${C_RST}"
err="${C_RED}✗${C_RST}"

print_repo_row() {
  local name=$1 path=$2
  if [ ! -d "$path/.git" ]; then
    printf "  %-10s %s%s%s\n" "$name" "$err" " missing at $path" ""
    return
  fi

  local branch tag dirty ahead behind ci
  branch=$(git -C "$path" rev-parse --abbrev-ref HEAD 2>/dev/null)
  tag=$(git -C "$path" describe --tags --exact-match 2>/dev/null || echo "—")
  if [ -z "$(git -C "$path" status --porcelain 2>/dev/null)" ]; then
    dirty="${ok} clean"
  else
    local n
    n=$(git -C "$path" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
    dirty="${warn} $n dirty"
  fi
  # Commits ahead/behind upstream (or origin/main if no tracking)
  local upstream
  upstream=$(git -C "$path" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || echo "origin/main")
  read -r ahead behind <<<"$(git -C "$path" rev-list --left-right --count "HEAD...$upstream" 2>/dev/null || echo "? ?")"

  # Latest CI conclusion on the branch (gh-only)
  if command -v gh >/dev/null 2>&1; then
    ci=$(cd "$path" && gh run list --branch "$branch" --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "?")
    case "$ci" in
      success) ci="${ok} ci";;
      failure) ci="${err} ci";;
      "") ci="${C_DIM}— ci${C_RST}";;
      *) ci="${warn} ci:$ci";;
    esac
  else
    ci="${C_DIM}gh? ci${C_RST}"
  fi

  printf "  %-10s %-6s %-8s %-15s ↑%s ↓%s  %s\n" \
    "$name" "$branch" "$tag" "$dirty" "$ahead" "$behind" "$ci"
}

contract_pin() {
  # Reads the pin that the consumer's *current branch* records, not the
  # working-tree state of the submodule (which can drift if you're mid-edit).
  local consumer=$1
  local sha
  sha=$(git -C "$consumer" ls-tree HEAD contract 2>/dev/null | awk '{print $3}')
  if [ -z "$sha" ]; then
    echo "no-submodule"; return
  fi
  # Describe the recorded SHA using refs from the submodule clone.
  git -C "$consumer/contract" describe --tags --exact-match "$sha" 2>/dev/null || \
    git -C "$consumer/contract" describe --tags --always "$sha" 2>/dev/null || \
    echo "${sha:0:7}"
}

latest_contract_tag() {
  if [ -d "$CONTRACT/.git" ]; then
    git -C "$CONTRACT" describe --tags "$(git -C "$CONTRACT" rev-list --tags --max-count=1 2>/dev/null)" 2>/dev/null || echo "?"
  else
    echo "?"
  fi
}

print_open_prs() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "  (gh not installed)"
    return
  fi
  local any=0
  for pair in "backend:$BACKEND" "android:$ANDROID" "dashboard:$DASHBOARD" "contract:$CONTRACT"; do
    local name=${pair%%:*} path=${pair#*:}
    [ -d "$path/.git" ] || continue
    while IFS=$'\t' read -r num title; do
      [ -z "$num" ] && continue
      printf "  %-10s #%s  %s\n" "$name" "$num" "$title"
      any=1
    done < <(cd "$path" && gh pr list --state open --json number,title --jq '.[] | "\(.number)\t\(.title)"' 2>/dev/null)
  done
  [ "$any" = "0" ] && echo "  ${C_DIM}(none)${C_RST}"
}

print_stb_state() {
  if ! command -v adb >/dev/null 2>&1; then
    echo "  ${C_DIM}(adb not installed)${C_RST}"
    return
  fi

  local stb_serial="192.168.10.189:5555"
  local connected
  connected=$(adb devices 2>/dev/null | awk -v s="$stb_serial" '$1==s && $2=="device"{print "yes"}')
  if [ -z "$connected" ]; then
    printf "  STB (%s):  %s unreachable\n" "$stb_serial" "$err"
    return
  fi

  local installed_code installed_name
  installed_code=$(adb -s "$stb_serial" shell pm dump com.hotwire.fisiontv.networkqual 2>/dev/null | awk -F= '/versionCode=/ { sub(/ .*/, "", $2); print $2; exit }')
  installed_name=$(adb -s "$stb_serial" shell pm dump com.hotwire.fisiontv.networkqual 2>/dev/null | awk -F= '/versionName=/ { print $2; exit }')

  # Active manifest from the local backend
  local active_code active_name active=""
  if curl -s --max-time 5 -H "Authorization: Bearer dev-admin-token-change-me" http://localhost:8080/admin/app-versions >/tmp/.fisiontv-status-active.json 2>/dev/null; then
    active=$(python3 -c "
import json
try:
    d = json.load(open('/tmp/.fisiontv-status-active.json'))
    a = next((i for i in d['items'] if i.get('isActive')), None)
    if a:
        print(f\"{a['latestVersionCode']} / {a['latestVersionName']}\")
except Exception:
    pass
" 2>/dev/null)
  fi

  printf "  STB:          %s installed: code %s / %s\n" "$ok" "$installed_code" "$installed_name"
  if [ -n "$active" ]; then
    printf "  Manifest:     %s active:    %s\n" "$ok" "$active"
    if [ "$installed_code / $installed_name" = "$active" ]; then
      printf "  Sync:         %s STB matches active manifest\n" "$ok"
    else
      printf "  Sync:         %s STB %s vs manifest %s\n" "$warn" "$installed_code / $installed_name" "$active"
    fi
  else
    printf "  Manifest:     %s no active manifest (or backend unreachable)\n" "$warn"
  fi
}

# ────────────────────────────────────────────────────────────────────────────
# Report
# ────────────────────────────────────────────────────────────────────────────

now=$(date -u +'%Y-%m-%d %H:%M UTC')
echo "${C_BLD}FisionTV+ release-train status${C_RST} — $now"
echo

echo "${C_BLU}Per repo:${C_RST}"
print_repo_row "contract"  "$CONTRACT"
print_repo_row "backend"   "$BACKEND"
print_repo_row "android"   "$ANDROID"
print_repo_row "dashboard" "$DASHBOARD"
echo

# Cross-repo alignment
b_pin=$(contract_pin "$BACKEND")
a_pin=$(contract_pin "$ANDROID")
latest=$(latest_contract_tag)
echo "${C_BLU}Contract alignment:${C_RST}"
printf "  latest tag:   %s\n" "$latest"
printf "  backend pin:  %s\n" "$b_pin"
printf "  android pin:  %s\n" "$a_pin"
if [ "$b_pin" = "$a_pin" ] && [ "$b_pin" = "$latest" ]; then
  printf "  status:       %s all aligned at %s\n" "$ok" "$latest"
elif [ "$b_pin" = "$a_pin" ]; then
  printf "  status:       %s consumers aligned at %s, but latest tag is %s\n" "$warn" "$b_pin" "$latest"
else
  printf "  status:       %s drift — backend %s vs android %s\n" "$err" "$b_pin" "$a_pin"
fi
echo

echo "${C_BLU}Open PRs:${C_RST}"
print_open_prs
echo

echo "${C_BLU}Lab STB:${C_RST}"
print_stb_state
