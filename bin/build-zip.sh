#!/usr/bin/env bash
# Builds dist/jat-site-shield.zip with the plugin in an jat-site-shield/ folder.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist build && mkdir -p dist build/jat-site-shield
tar --exclude-vcs --exclude=./.github --exclude=./bin --exclude=./dist --exclude=./build \
    --exclude=./docs --exclude=./.wordpress-org --exclude=./.gitignore --exclude=./.distignore --exclude=./README.md \
    --exclude='.DS_Store' -cf - . | tar -xf - -C build/jat-site-shield
(cd build && zip -qr ../dist/jat-site-shield.zip jat-site-shield)
rm -rf build
echo "Built dist/jat-site-shield.zip"
