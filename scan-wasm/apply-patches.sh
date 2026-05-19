#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIE_ROOT="${DIE_ROOT:-$HERE/third_party/DIE-engine}"
PATCHES="$HERE/patches"

if [[ ! -d "$DIE_ROOT" ]]; then
  echo "apply-patches: $DIE_ROOT not found - did you run 'git submodule update --init --recursive'?" >&2
  exit 1
fi

shopt -s nullglob
for p in "$PATCHES"/*.patch; do
  sub="$(basename "$p" .patch)"
  d="$DIE_ROOT/$sub"
  if [[ ! -d "$d" ]]; then
    echo "apply-patches: skip $sub.patch - $d not present" >&2
    continue
  fi
  if git -C "$d" apply --reverse --check "$p" >/dev/null 2>&1; then
    echo "apply-patches: $sub already applied"
  elif git -C "$d" apply --check "$p" >/dev/null 2>&1; then
    git -C "$d" apply "$p"
    echo "apply-patches: $sub applied"
  else
    echo "apply-patches: WARNING - $sub.patch does not apply cleanly (DIE-engine moved? merged upstream?), skipping" >&2
  fi
done
