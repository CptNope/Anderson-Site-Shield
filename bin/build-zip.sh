#!/usr/bin/env bash
# Builds dist/jat-site-shield.zip with the plugin in a jat-site-shield/ folder.
# Everything listed in .distignore (development files, docs, repo assets) is left out.
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf dist build && mkdir -p dist build/jat-site-shield
EXCLUDES=()
while IFS= read -r line; do
	[ -z "$line" ] && continue
	case "$line" in
		/*) EXCLUDES+=( "--exclude=.${line}" ) ;;
		*)  EXCLUDES+=( "--exclude=${line}" ) ;;
	esac
done < .distignore
tar "${EXCLUDES[@]}" -cf - . | tar -xf - -C build/jat-site-shield
(cd build && zip -qr ../dist/jat-site-shield.zip jat-site-shield)
rm -rf build
echo "Built dist/jat-site-shield.zip"
