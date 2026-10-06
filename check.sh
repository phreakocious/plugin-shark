#!/bin/sh
# Install this repo as the personal Lua plugin dir of a throwaway HOME, then
# fail if tshark skips any .lua file or reports any Lua error, at load time or
# while dissecting test.pcap (TCP + HTTP over loopback).
set -eu
repo=$(cd "$(dirname "$0")" && pwd)
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
mkdir -p "$home/.local/lib/wireshark"
ln -s "$repo" "$home/.local/lib/wireshark/plugins"

tshark --version | head -1
HOME=$home tshark -G plugins >"$home/plugins" 2>"$home/err" || { cat "$home/err"; exit 1; }
HOME=$home tshark -r "$repo/test.pcap" -V >"$home/dissect" 2>>"$home/err" || { cat "$home/err"; exit 1; }
if [ -s "$home/err" ]; then cat "$home/err"; exit 1; fi
if grep 'Lua Error' "$home/dissect"; then exit 1; fi

find "$repo" -name .git -prune -o -name '*.lua' -print | sed 's#.*/##' | sort >"$home/want"
awk -F'\t' -v p="$home/" '$3 == "Lua script" && index($4, p) == 1 {print $1}' "$home/plugins" | sort >"$home/got"
diff "$home/want" "$home/got" && echo "OK: $(wc -l <"$home/got" | tr -d ' ') Lua plugins loaded, no errors"
