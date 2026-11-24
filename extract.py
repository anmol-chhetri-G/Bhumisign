#!/usr/bin/env python3
"""Usage: python3 extract.py BHUMISIGN_BUILD.md
Writes every code block that sits under a heading of the form: #### `path/to/file`
"""
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
pattern = re.compile(r"^#### `([^`]+)`\s*\n```[a-z]*\n(.*?)\n```\s*$", re.S | re.M)
count = 0
for match in pattern.finditer(text):
    path = pathlib.Path(match.group(1))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(match.group(2) + "\n", encoding="utf-8")
    print("wrote", path)
    count += 1
print(count, "files written")
