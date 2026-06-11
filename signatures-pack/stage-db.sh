#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
DIE_ROOT="${DIE_ROOT:-$HERE/../scan-wasm/third_party/DIE-engine}"

if [[ ! -d "$DIE_ROOT/Detect-It-Easy/db" ]]; then
  echo "error: $DIE_ROOT/Detect-It-Easy/db not found" >&2
  echo "set DIE_ROOT=/path/to/DIE-engine or run 'git submodule update --init --recursive'" >&2
  exit 1
fi

if [[ -x "$HERE/../scan-wasm/apply-patches.sh" && "$DIE_ROOT" == "$HERE/../scan-wasm/third_party/DIE-engine" ]]; then
  "$HERE/../scan-wasm/apply-patches.sh"
fi

rm -rf "$DIST"
mkdir -p "$DIST"

copied_dbs=()
for db in db db_extra db_custom; do
  src="$DIE_ROOT/Detect-It-Easy/$db"
  if [[ -d "$src" ]]; then
    cp -R "$src" "$DIST/$db"
    copied_dbs+=("$db")
  fi
done

peid_src="$DIE_ROOT/Detect-It-Easy/peid_rules/PE/userdb.txt"
if [[ -f "$peid_src" ]]; then
  mkdir -p "$DIST/peid"
  cp "$peid_src" "$DIST/peid/userdb.txt"
fi

yara_src="$DIE_ROOT/XYara/yara_rules"
if [[ -d "$yara_src" ]]; then
  mkdir -p "$DIST/yara"
  yara_files=(
    DiE_BasicHeuristics_by_DosX.yar
    DiE_InterestingThings_by_DosX.yar
    DiE_EnhancedHeuristics_by_DosX.yar
    DosX_Heuristic.yar
    packer_compiler_signatures.yar
    crypto_signature.yar
    malware_analisys.yar
    packer.yar
    peid.yar
  )
  staged=()
  for f in "${yara_files[@]}"; do
    if [[ -f "$yara_src/$f" ]]; then cp "$yara_src/$f" "$DIST/yara/$f"; staged+=("$f"); fi
  done
  python3 - "$DIST/yara" "${staged[@]}" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1]); files = sys.argv[2:]
idx = [{"name": f, "path": f"yara/{f}", "size": (d / f).stat().st_size} for f in files]
(d / "index.json").write_text(json.dumps({"rules": idx}, indent=2) + "\n")
PY
fi

python3 - "$DIST" "${copied_dbs[@]}" <<'PY'
import json, os, sys
from pathlib import Path

dist = Path(sys.argv[1])
dbs  = sys.argv[2:]

ROOT_SKIP = {"info.ini", "about.txt"}

manifest = {"version": 1, "dbs": {}}
for db in dbs:
    db_root = dist / db
    if not db_root.is_dir():
        continue
    formats = {}
    for fmt_dir in sorted(p for p in db_root.iterdir() if p.is_dir() and not p.name.startswith(".")):
        entries = []
        for f in sorted(fmt_dir.rglob("*")):
            if not f.is_file():
                continue
            rel = f.relative_to(dist).as_posix()
            kind = "init" if f.name == "_init" else ("sg" if f.suffix == ".sg" else "other")
            entries.append({"path": rel, "size": f.stat().st_size, "kind": kind})
        if any(e["kind"] in ("sg", "init") for e in entries):
            formats[fmt_dir.name] = entries

    root_entries = []
    for f in sorted(p for p in db_root.iterdir() if p.is_file() and not p.name.startswith(".")):
        if f.name in ROOT_SKIP:
            continue
        rel = f.relative_to(dist).as_posix()
        kind = "init" if f.name == "_init" else "include"
        root_entries.append({"path": rel, "size": f.stat().st_size, "kind": kind})
    if root_entries:
        formats["_root"] = root_entries

    manifest["dbs"][db] = formats

(dist / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
