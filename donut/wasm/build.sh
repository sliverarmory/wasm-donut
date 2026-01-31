#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_WASM="${ROOT_DIR}/donut/wasm/donut.wasm"
EM_CACHE_DIR="${ROOT_DIR}/.emscripten_cache"

EMCC_BIN="${EMCC:-emcc}"

mkdir -p "${EM_CACHE_DIR}"

EM_CACHE="${EM_CACHE_DIR}" "${EMCC_BIN}" \
  -O2 \
  -I "${ROOT_DIR}/donut/include" \
  "${ROOT_DIR}/donut/wasm/donut_wasm.c" \
  "${ROOT_DIR}/donut/hash.c" \
  "${ROOT_DIR}/donut/encrypt.c" \
  "${ROOT_DIR}/donut/format.c" \
  "${ROOT_DIR}/donut/loader/clib.c" \
  "${ROOT_DIR}/donut/wasm/aplib_stub.c" \
  -sSTANDALONE_WASM=1 \
  -sALLOW_MEMORY_GROWTH=1 \
  -Wl,--no-entry \
  -sERROR_ON_UNDEFINED_SYMBOLS=1 \
  -sEXPORTED_FUNCTIONS='["_donut_generate","_malloc","_free"]' \
  -o "${OUT_WASM}"

echo "Wrote ${OUT_WASM}"
