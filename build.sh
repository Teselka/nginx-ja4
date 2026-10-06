#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_SRC="${NGINX_SRC:-/usr/src/nginx}"
BUILD="$ROOT/nginx-build"

if [[ "${1:-}" == clean ]]; then
    rm -rf "$BUILD"
    exit 0
fi

mkdir -p "$BUILD"
cd "$BUILD"
ln -sfn "$NGINX_SRC/auto" auto
ln -sfn "$NGINX_SRC/src" src

if [[ ! -f Makefile || "$ROOT/config" -nt Makefile ]]; then
    auto/configure \
        --with-compat \
        --with-http_ssl_module \
        --add-dynamic-module="$ROOT" >configure.log 2>&1 \
        || { tail -n 20 configure.log >&2; exit 1; }
fi

make -j"$(nproc)" modules

echo "module: $BUILD/objs/ngx_http_ja4_module.so"
