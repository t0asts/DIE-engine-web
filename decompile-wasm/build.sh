#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
BUILD="$HERE/build"
GHIDRA_ROOT="$HERE/third_party/ghidra"

if [[ "${EMSDK:-}" == "" ]] && ! command -v em++ >/dev/null; then
    echo "error: emsdk not active. Source emsdk_env.sh or run inside the dev container." >&2
    exit 1
fi

if [[ ! -e "$GHIDRA_ROOT/Ghidra/Features/Decompiler/src/decompile/cpp/libdecomp.cc" ]]; then
    echo "error: $GHIDRA_ROOT not populated - run: git submodule update --init --recursive" >&2
    exit 1
fi

if [[ -f "$BUILD/CMakeCache.txt" ]]; then
    cached_home="$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' "$BUILD/CMakeCache.txt" || true)"
    if [[ "$cached_home" != "$HERE" ]]; then
        echo "    stale build cache (configured for: ${cached_home:-unknown}); wiping $BUILD"
        rm -rf "$BUILD"
    fi
fi
mkdir -p "$BUILD"
( cd "$BUILD" && emcmake cmake "$HERE" -DCMAKE_BUILD_TYPE=Release )

cmake --build "$BUILD" --parallel "$(nproc 2>/dev/null || echo 4)"

mkdir -p "$DIST"
cp "$BUILD/decompile_engine.js"   "$DIST/"
cp "$BUILD/decompile_engine.wasm" "$DIST/"

ls -lh "$DIST"/decompile_engine.{js,wasm}
