#!/bin/bash
# netmon 실행기. 파이썬 3.9 이상을 찾아서 넘긴다.
set -eu
# 심볼릭 링크로 걸어 두고 어디서나 부를 수 있어야 한다. $0 이 링크면
# dirname 은 링크가 놓인 곳(예: /opt/homebrew/bin)을 가리키므로, 실제
# 저장소를 찾으려면 링크를 끝까지 따라가야 한다.
src=$0
while [ -L "$src" ]; do
  target=$(readlink "$src")
  case $target in
    /*) src=$target ;;
    *)  src=$(cd "$(dirname "$src")" && pwd)/$target ;;
  esac
done
here=$(cd "$(dirname "$src")" && pwd)

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
