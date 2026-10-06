#!/bin/sh
# Install this repo in the personal Lua plugin dir of a throwaway HOME, then
# fail if tshark skips any .lua file or reports any Lua error, at load time or
# while dissecting test.pcap (TCP + HTTP over loopback).
set -eu
repo=$(cd "$(dirname "$0")" && pwd)
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
mkdir -p "$home/.local/lib/wireshark/plugins"
ln -s "$repo" "$home/.local/lib/wireshark/plugins/plugin-shark"

HOME=$home tshark --version | head -1
HOME=$home tshark -G plugins >"$home/plugins" 2>"$home/err" || { cat "$home/err"; exit 1; }
# One pass and two (-2): some post-dissectors only build their tree when
# pinfo.visited is set, which a single pass never does. Without -R, tshark
# 4.6's first pass hands Lua Field extractors nil.
HOME=$home tshark -r "$repo/test.pcap" -V >"$home/dissect" 2>>"$home/err" || { cat "$home/err"; exit 1; }
HOME=$home tshark -r "$repo/test.pcap" -V -2 -R frame >>"$home/dissect" 2>>"$home/err" || { cat "$home/err"; exit 1; }
# tcp_stats is not auto-loaded; run it the way its header says to.
HOME=$home tshark -r "$repo/test.pcap" -q -n -o tcp.calculate_timestamps:TRUE \
  -X lua_script:"$repo/tcp_stats.lua.disabled" >"$home/tcp_stats" 2>>"$home/err" || { cat "$home/err"; exit 1; }
grep -q '^Stream ' "$home/tcp_stats" || { echo "tcp_stats printed no streams"; cat "$home/tcp_stats"; exit 1; }
if [ -s "$home/err" ]; then cat "$home/err"; exit 1; fi
if grep -q '^Lua Error' "$home/dissect"; then grep '^Lua Error' "$home/dissect" | sort | uniq -c; exit 1; fi

find "$repo" -name .git -prune -o -name '*.lua' -print | sed 's#.*/##' | sort >"$home/want"
awk -F'\t' -v p="$home/" '$3 == "Lua script" && index($4, p) == 1 {print $1}' "$home/plugins" | sort >"$home/got"
diff "$home/want" "$home/got" && echo "OK: $(wc -l <"$home/got" | tr -d ' ') Lua plugins loaded, no errors"
