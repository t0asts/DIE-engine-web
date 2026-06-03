#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$HERE/dist"
BUILD="$HERE/build"
GHIDRA_ROOT="${GHIDRA_ROOT:-$HERE/../decompile-wasm/third_party/ghidra}"
CPP="$GHIDRA_ROOT/Ghidra/Features/Decompiler/src/decompile/cpp"
PROC="$GHIDRA_ROOT/Ghidra/Processors"
SLEIGH="$BUILD/sleigh"
CXX="${CXX:-g++}"

die() { echo "stage-specs: error: $*" >&2; exit 1; }

[[ -f "$CPP/slgh_compile.cc" ]] || \
  die "$GHIDRA_ROOT not populated - run: git submodule update --init --recursive"

declare -A SPECS=(
  [x86]="x86 x86-64"
  [ARM]="ARM7_le ARM7_be"
  [AARCH64]="AARCH64 AARCH64BE"
)

PLATFORM="$(uname -s)-$(uname -m)"
if [[ -x "$SLEIGH" && "$(cat "$BUILD/.platform" 2>/dev/null || true)" == "$PLATFORM" ]]; then
  :
else
  rm -rf "$BUILD"
  mkdir -p "$BUILD"
  CORE="xml marshal space float address pcoderaw translate opcodes globalcontext"
  SLGH="sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics context slaformat compression filemanage"
  SLACOMP="slgh_compile slghparse slghscan"
  srcs=()
  for n in $CORE $SLGH $SLACOMP; do srcs+=("$CPP/$n.cc"); done
  "$CXX" -std=c++17 -O2 -w -o "$SLEIGH" "${srcs[@]}" -lz
  echo "$PLATFORM" > "$BUILD/.platform"
fi

rm -rf "$DIST"
mkdir -p "$DIST"
for arch in "${!SPECS[@]}"; do
  srcdir="$PROC/$arch/data/languages"
  dstdir="$DIST/$arch/data/languages"
  [[ -d "$srcdir" ]] || die "missing processor dir: $srcdir"
  mkdir -p "$dstdir"

  for base in ${SPECS[$arch]}; do
    [[ -f "$srcdir/$base.slaspec" ]] || die "missing $srcdir/$base.slaspec"
    "$SLEIGH" "$srcdir/$base.slaspec" "$dstdir/$base.sla"
  done

  for ext in ldefs cspec pspec opinion; do
    for f in "$srcdir"/*."$ext"; do
      [[ -f "$f" ]] && cp "$f" "$dstdir/"
    done
  done
done

python3 - "$DIST" <<'PY'
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
files = []
for p in sorted(root.rglob("*")):
    if p.is_file() and p.name != "manifest.json":
        files.append({"path": p.relative_to(root).as_posix(), "size": p.stat().st_size})
(root / "manifest.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
PY
