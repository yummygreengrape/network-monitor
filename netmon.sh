#!/bin/bash
# netmon 실행기. 파이썬 3.9 이상을 찾아서 넘긴다.
set -eu
here=$(cd "$(dirname "$0")" && pwd)

# launchd 는 PATH 로 /usr/bin:/bin:/usr/sbin:/sbin 만 준다. 사용자가 설치한
# VPN 도구는 대부분 아래 두 곳에 있다. 시스템 경로를 앞에 두어 가리지 않는다.
export PATH="$PATH:/usr/local/bin:/opt/homebrew/bin"
for py in python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 /usr/bin/python3; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    exec env PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}" "$py" -m netmon "$@"
  fi
done
echo "python3 3.9 이상을 찾지 못했다. Xcode Command Line Tools 를 설치하면 /usr/bin/python3 가 생긴다." >&2
exit 1
