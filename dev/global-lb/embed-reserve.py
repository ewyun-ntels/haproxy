#!/usr/bin/env python3
"""Mechanical Lua-to-C generator. Not required to build the shipped C source."""
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
source = (root / "dev/global-lb/reserve.lua").read_text(encoding="ascii")
output = "/* Generated from dev/global-lb/reserve.lua; do not edit.\n" \
         " * UD-007/009/011 v2-r1-20261003. */\n" \
         "static const char global_lb_reserve_lua[] =\n"
output += "\n".join(json.dumps(line) for line in source.splitlines(keepends=True)) + ";\n"
target = root / "include/haproxy/global_lb_reserve_script.h"
if "--check" in sys.argv:
    if not target.exists() or target.read_text(encoding="ascii") != output:
        sys.exit("reservation Lua/C mismatch: run dev/global-lb/embed-reserve.py")
else:
    target.write_text(output, encoding="ascii", newline="\n")
