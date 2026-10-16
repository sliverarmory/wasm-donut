#!/bin/sh
set -eu

case "${1:-all}" in
  x86)
    target="loader-x86"
    ;;
  amd64)
    target="loader-x64"
    ;;
  arm64)
    target="loader-arm64"
    ;;
  all)
    target="loaders"
    ;;
  *)
    echo "unsupported architecture; use x86, amd64, arm64 or all" >&2
    exit 64
    ;;
esac

exec make -f Makefile.mingw "$target"
