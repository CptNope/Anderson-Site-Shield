#!/usr/bin/env bash
# Builds dist/anderson-site-shield.zip with the plugin in an anderson-site-shield/ folder.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist build && mkdir -p dist build/anderson-site-shield
tar --exclude-vcs --exclude=./.github --exclude=./bin --exclude=./dist --exclude=./build \
    --exclude=./docs --exclude=./.gitignore --exclude=./.distignore --exclude=./README.md \
    --exclude='.DS_Store' -cf - . | tar -xf - -C build/anderson-site-shield
(cd build && zip -qr ../dist/anderson-site-shield.zip anderson-site-shield)
rm -rf build
echo "Built dist/anderson-site-shield.zip"
