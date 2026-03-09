#!/usr/bin/env bash
# read if needed https://astyle.sourceforge.net/astyle.html
shopt -s nullglob
files=(*.c *.h)
if [[ ${#files[@]} -eq 0 ]]; then
    echo "style.sh: no .c/.h files found in $(pwd)" >&2
    exit 1
fi
astyle --style=bsd \
    --indent-switches \
    --indent-cases \
    --max-code-length=80 \
    --add-braces \
    --convert-tabs \
    --suffix=none \
    --align-pointer=type \
    --align-reference=type \
    "${files[@]}"
