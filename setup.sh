#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PORT=8080
RUN=1
REBUILD_DEV=0
CLEAN=0
CONTAINER_NAME=die-web
DEV_IMAGE=die-web-dev
RUNTIME_IMAGE=die-web-runtime
SUBMODULE_DIR=scan-wasm/third_party/DIE-engine
GHIDRA_DIR=decompile-wasm/third_party/ghidra

usage() {
  cat <<'EOF'
  ./setup.sh                  full setup, host on http://localhost:8080
  ./setup.sh --port 9000      ...on a different host port
  ./setup.sh --no-run         build everything, don't start a container
  ./setup.sh --rebuild-dev    force-rebuild the dev toolchain image (slow)
  ./setup.sh --clean          remove the die-web container + die-web-dev /
                              die-web-runtime images, then exit (build
                              artifacts on disk are left alone)
  ./setup.sh -h | --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)        PORT="${2:?--port needs a value}"; shift 2 ;;
    --port=*)      PORT="${1#*=}"; shift ;;
    --no-run)      RUN=0; shift ;;
    --rebuild-dev) REBUILD_DEV=1; shift ;;
    --clean)       CLEAN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "setup.sh: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not on PATH - install Docker (see README.md)"
docker info >/dev/null 2>&1 || die "Docker daemon unreachable - running? user in 'docker' group, or need sudo?"
command -v git >/dev/null 2>&1 || warn "git not found - skipping submodules; ensure $SUBMODULE_DIR is populated"

if [[ "$CLEAN" == 1 ]]; then
  if docker container inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "  rm container $CONTAINER_NAME"
    docker rm -f "$CONTAINER_NAME" >/dev/null
  else
    echo "  container $CONTAINER_NAME: not present"
  fi
  for img in "$RUNTIME_IMAGE" "$DEV_IMAGE"; do
    if docker image inspect "$img" >/dev/null 2>&1; then
      echo "  rm image $img"
      docker rmi "$img" >/dev/null 2>&1 || docker rmi -f "$img" >/dev/null 2>&1 \
        || warn "couldn't remove $img - still in use?"
    else
      echo "  image $img: not present"
    fi
  done
  exit 0
fi

GHIDRA_SENTINEL="$GHIDRA_DIR/Ghidra/Features/Decompiler/src/decompile/cpp/libdecomp.cc"
if command -v git >/dev/null 2>&1 && [[ -e .git ]] && [[ -f .gitmodules ]]; then
  if [[ ! -e "$SUBMODULE_DIR/Detect-It-Easy/db" ]] || [[ ! -e "$GHIDRA_SENTINEL" ]]; then
    git submodule update --init --recursive
  fi
fi

[[ -e "$SUBMODULE_DIR/Detect-It-Easy/db" ]] || \
  die "$SUBMODULE_DIR not populated - run: git submodule update --init --recursive"
[[ -e "$GHIDRA_SENTINEL" ]] || \
  die "$GHIDRA_DIR not populated - run: git submodule update --init --recursive"

if [[ "$REBUILD_DEV" == 1 ]] || ! docker image inspect "$DEV_IMAGE" >/dev/null 2>&1; then
  say "Building $DEV_IMAGE (~30-45 min, ~10 GB)"
  docker build -t "$DEV_IMAGE" -f docker/Dockerfile.dev .
else
  say "$DEV_IMAGE exists - skipping (--rebuild-dev to force)"
fi

dev_run() { docker run --rm -v "$PWD":/work "$@"; }

dev_run -w /work/scan-wasm "$DEV_IMAGE" ./build.sh
dev_run -w /work "$DEV_IMAGE" ./signatures-pack/stage-db.sh
dev_run -w /work/decompile-wasm "$DEV_IMAGE" ./build.sh
dev_run -w /work "$DEV_IMAGE" ./specs/stage-specs.sh
dev_run -w /work/web "$DEV_IMAGE" bash -c 'npm ci && npm run build'

say "Building $RUNTIME_IMAGE"
if ! docker build -t "$RUNTIME_IMAGE" -f docker/Dockerfile.runtime . ; then
  warn "Dockerfile.runtime failed (nginx:1.27-alpine pull?) - trying Dockerfile.runtime.local"
  docker image inspect "$RUNTIME_IMAGE" >/dev/null 2>&1 || \
    die "Dockerfile.runtime.local needs $RUNTIME_IMAGE base - pull nginx:1.27-alpine (or fix Docker Hub access) and re-run"
  docker build -t "$RUNTIME_IMAGE" -f docker/Dockerfile.runtime.local .
fi

if [[ "$RUN" == 1 ]]; then
  say "Starting $CONTAINER_NAME on port $PORT"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER_NAME" -p "$PORT:80" --restart unless-stopped "$RUNTIME_IMAGE" >/dev/null
  printf '\033[1;32mup:\033[0m http://localhost:%s\n' "$PORT"
  echo "  logs: docker logs -f $CONTAINER_NAME"
  echo "  stop: docker rm -f $CONTAINER_NAME"
else
  printf '\033[1;32mbuilt:\033[0m %s\n' "$RUNTIME_IMAGE"
  echo "run: docker run -d --name $CONTAINER_NAME -p $PORT:80 --restart unless-stopped $RUNTIME_IMAGE"
fi

echo "clean build dirs: docker run --rm -v \"\$PWD\":/work $DEV_IMAGE rm -rf /work/scan-wasm/build /work/decompile-wasm/build /work/specs/build"
