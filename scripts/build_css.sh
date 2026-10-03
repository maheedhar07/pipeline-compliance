#!/usr/bin/env bash
# Build src/pch/web/static/vendor/tailwind.css with the pinned *standalone* Tailwind CLI (no Node, no npm).
# The binary is downloaded from the official GitHub release and verified against the sha256 values below
# (these match the release's published sha256sums.txt) before it is executed. It is cached in .tools/ (gitignored).
#
#   scripts/build_css.sh          # rebuild and update static/vendor/tailwind.css + MANIFEST.json sha256
#   scripts/build_css.sh --check  # fail if the committed CSS differs from a fresh build (used by CI)
#
# To bump: change VERSION, fetch the new sha256sums.txt from the release page, update the two hashes, rebuild.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="3.4.17"
SHA_MACOS_ARM64="a1d0c7985759accca0bf12e51ac1dcbf0f6cf2fffb62e6e0f62d091c477a10a3"
SHA_MACOS_X64="6cbdad74be776c087ffa5e9a057512c54898f9fe8828d3362212dfe32fc933a3"
SHA_LINUX_X64="7d24f7fa191d2193b78cd5f5a42a6093e14409521908529f42d80b11fde1f1d4"
SHA_LINUX_ARM64="69b1378b8133192d7d2feb12a116fa12d035594f58db3eff215879e4ad8cf39b"

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) ASSET="tailwindcss-macos-arm64"; WANT="$SHA_MACOS_ARM64" ;;
  Darwin-x86_64) ASSET="tailwindcss-macos-x64"; WANT="$SHA_MACOS_X64" ;;
  Linux-x86_64) ASSET="tailwindcss-linux-x64"; WANT="$SHA_LINUX_X64" ;;
  Linux-aarch64|Linux-arm64) ASSET="tailwindcss-linux-arm64"; WANT="$SHA_LINUX_ARM64" ;;
  *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

BIN=".tools/${ASSET}-${VERSION}"
if [ ! -x "$BIN" ] || [ "$(sha256 "$BIN")" != "$WANT" ]; then
  mkdir -p .tools
  curl -fsSL -o "$BIN.tmp" "https://github.com/tailwindlabs/tailwindcss/releases/download/v${VERSION}/${ASSET}"
  GOT="$(sha256 "$BIN.tmp")"
  if [ "$GOT" != "$WANT" ]; then rm -f "$BIN.tmp"; echo "checksum mismatch for $ASSET: got $GOT want $WANT" >&2; exit 1; fi
  chmod +x "$BIN.tmp"; mv "$BIN.tmp" "$BIN"
fi

OUT="src/pch/web/static/vendor/tailwind.css"
TMP="$(mktemp)"
"$BIN" -c tailwind.config.js -i src/pch/web/tailwind/input.css -o "$TMP" --minify
if [ "${1:-}" = "--check" ]; then
  if ! cmp -s "$TMP" "$OUT"; then echo "$OUT is stale: run scripts/build_css.sh" >&2; rm -f "$TMP"; exit 1; fi
  rm -f "$TMP"; echo "tailwind.css up to date"; exit 0
fi
chmod 644 "$TMP"; mv "$TMP" "$OUT"
python3 - "$OUT" <<'PY'
import hashlib, json, sys
m = "src/pch/web/static/vendor/MANIFEST.json"
d = json.load(open(m))
for a in d["assets"]:
    if a["file"] == "tailwind.css":
        a["sha256"] = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
json.dump(d, open(m, "w"), indent=2)
open(m, "a").write("\n")
PY
echo "built $OUT"
