#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIST="$HERE/dist"
BUILD="$HERE/build"

if [[ "${EMSDK:-}" == "" ]] && ! command -v em++ >/dev/null; then
    echo "error: emsdk not active. Source emsdk_env.sh or run inside the dev container." >&2
    exit 1
fi

if [[ -z "${Qt6_DIR:-}" ]]; then
    echo "warning: Qt6_DIR is unset; relying on CMake's find_package fallbacks." >&2
fi

"$HERE/apply-patches.sh"

( cd "$HERE/shim-gen" && [[ -d node_modules ]] || npm install --silent )
( cd "$HERE/shim-gen" && npm run build --silent )

echo "==> [2/4] Configuring (emcmake)"
mkdir -p "$BUILD"

QT_WASM_PREFIX="${QT_WASM_PREFIX:-/opt/qt-wasm}"
CMAKE_QT_ARGS=()
if [[ -d "$QT_WASM_PREFIX" ]]; then
    CMAKE_QT_ARGS+=(
      "-DCMAKE_PREFIX_PATH=$QT_WASM_PREFIX"
      "-DQt6_DIR=$QT_WASM_PREFIX/lib/cmake/Qt6"
      "-DCMAKE_FIND_ROOT_PATH=$QT_WASM_PREFIX"
      "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH"
    )
fi

( cd "$BUILD" && emcmake cmake "$HERE" -DCMAKE_BUILD_TYPE=Release "${CMAKE_QT_ARGS[@]}" )

cmake --build "$BUILD" --parallel "$(nproc 2>/dev/null || echo 4)"

mkdir -p "$DIST"
cp "$BUILD/scan_engine.js"   "$DIST/"
cp "$BUILD/scan_engine.wasm" "$DIST/"

ls -lh "$DIST"/scan_engine.{js,wasm}
