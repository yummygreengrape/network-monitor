#!/bin/bash
# 위치 권한 헬퍼 앱을 빌드한다.
#
#   tools/location-helper/build.sh [설치 위치]
#
# 기본 설치 위치는 $NETMON_HOME 또는 ~/.config/network-monitor 다.
#
# 왜 앱 번들인가
#   macOS 의 위치 권한(TCC)은 **앱 단위**다. 터미널에서 돌리는 스크립트는
#   권한을 요청할 주체가 없어서 요청 창이 뜨지 않는다. 실제로 단일 실행 파일로
#   requestWhenInUseAuthorization 을 불러 봤지만 75초 동안 아무 창도 뜨지 않았다.
#   번들로 만들어 LaunchServices(`open -n`)로 띄우면 뜬다.
#
# 왜 다시 빌드하면 권한을 다시 받아야 하는가
#   TCC 는 코드 서명으로 앱을 식별한다. 다시 서명하면 이전 승인이 무효가 된다.
#   실제로 재서명 직후 상태가 authorized-always 에서 not-determined 로 돌아갔다.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dest=${1:-${NETMON_HOME:-$HOME/.config/network-monitor}}
app="$dest/NetworkMonitorLocation.app"

command -v clang >/dev/null 2>&1 || {
  echo "clang 이 없습니다. Xcode Command Line Tools 를 설치하세요: xcode-select --install" >&2
  exit 1
}

mkdir -p "$app/Contents/MacOS"
cp "$here/Info.plist" "$app/Contents/Info.plist"

clang -fobjc-arc -mmacosx-version-min=11.0 \
  -framework Foundation -framework CoreLocation -framework CoreWLAN \
  -o "$app/Contents/MacOS/NetworkMonitorLocation" \
  "$here/request_location.m"

# 지정 요구사항을 번들 식별자로 고정한다. 그냥 서명하면 재빌드마다 cdhash 가
# 바뀌어 TCC 승인이 무효가 되고 사용자가 매번 다시 허용해야 한다.
codesign -s - --force --deep \
  -r='designated => identifier "io.github.network-monitor.location-helper"' \
  "$app" >/dev/null 2>&1 || {
  echo "서명에 실패했습니다. 권한 요청이 동작하지 않을 수 있습니다." >&2
}

echo "$app"
