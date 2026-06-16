#!/usr/bin/env bash
# Sparse, shallow checkout of the OWASP Benchmark — just the test sources + the
# answer key, not the full Maven project. Lands in ./benchmark (gitignored).
set -euo pipefail

DEST="${1:-benchmark}"
REPO="https://github.com/OWASP-Benchmark/BenchmarkJava"

if [ -d "$DEST/.git" ]; then
  echo "$DEST already exists — skipping clone"
  exit 0
fi

git clone --depth 1 --filter=blob:none --sparse "$REPO" "$DEST"
git -C "$DEST" sparse-checkout set src/main/java/org/owasp/benchmark/testcode

echo
echo "checked out:"
echo "  $(ls "$DEST"/expectedresults-*.csv 2>/dev/null || echo '(no CSV found at root!)')"
echo "  $(ls "$DEST"/src/main/java/org/owasp/benchmark/testcode/*.java 2>/dev/null | wc -l | tr -d ' ') test sources"
