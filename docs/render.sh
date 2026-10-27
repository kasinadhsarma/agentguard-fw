#!/usr/bin/env bash
# Render the Mermaid diagrams to PNG and build the PDF.
# Needs: mmdc (npm i -g @mermaid-js/mermaid-cli) and a LaTeX install (latexmk).
set -euo pipefail
cd "$(dirname "$0")"

if command -v mmdc >/dev/null 2>&1; then
  # chromium often needs --no-sandbox when running as root or in a container
  # set CHROME_PATH to a Chrome/Chromium binary if mmdc cannot find one
  if [ -n "${CHROME_PATH:-}" ]; then
    printf '{"executablePath":"%s","args":["--no-sandbox","--disable-setuid-sandbox"]}' "$CHROME_PATH" > diagrams/.puppeteer.json
  else
    echo '{"args": ["--no-sandbox", "--disable-setuid-sandbox"]}' > diagrams/.puppeteer.json
  fi
  for src in diagrams/*.mmd; do
    out="${src%.mmd}.png"
    echo "rendering $src"
    mmdc -i "$src" -o "$out" -p diagrams/.puppeteer.json -s 3 -b white -q
  done
  rm -f diagrams/.puppeteer.json
else
  echo "mmdc not found: building the PDF with Mermaid source instead of images"
fi

latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
echo "built docs/main.pdf"
