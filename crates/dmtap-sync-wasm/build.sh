#!/usr/bin/env bash
# Reproducible build of the WASM binding.
#
#   ./crates/dmtap-sync-wasm/build.sh          # both targets
#   ./crates/dmtap-sync-wasm/build.sh nodejs   # just the one the test suite loads
#
# Emits two packages from ONE compiled core:
#   pkg-node/    --target nodejs   — CommonJS, synchronous init; what `test/vectors.test.mjs` loads
#   pkg/         --target bundler  — ESM + `.d.ts`; the npm-consumable artifact for a web product
#
# Requires: rustup target add wasm32-unknown-unknown, and wasm-pack (https://rustwasm.github.io).
# wasm-pack fetches a `wasm-bindgen` CLI matching the version in Cargo.lock, so the JS glue and the
# compiled module can never drift apart.
set -euo pipefail

cd "$(dirname "$0")"

targets=("${@:-nodejs bundler}")
# shellcheck disable=SC2206
targets=(${targets[*]})

for target in "${targets[@]}"; do
  case "$target" in
    nodejs) out=pkg-node ;;
    bundler) out=pkg ;;
    web) out=pkg-web ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
  esac
  echo "==> wasm-pack build --target $target --out-dir $out"
  wasm-pack build --release --target "$target" --out-dir "$out" --out-name dmtap_sync
  size=$(wc -c <"$out/dmtap_sync_bg.wasm" | tr -d ' ')
  gz=$(gzip -9 -c "$out/dmtap_sync_bg.wasm" | wc -c | tr -d ' ')
  printf '    %s: %s bytes raw, %s bytes gzipped\n' "$out/dmtap_sync_bg.wasm" "$size" "$gz"
done

cat <<'EOF'

Next: run the cross-surface conformance proof.

  cargo test -p dmtap-sync-wasm --test native_trace     # the native half
  node --test 'crates/dmtap-sync-wasm/test/*.test.mjs'  # the WASM half + the byte-for-byte diff
EOF
