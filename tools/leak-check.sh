#!/bin/bash
# 커밋될 내용에 환경 식별자가 섞였는지 검사한다.
#
#   tools/leak-check.sh              스테이징된 변경(git diff --cached)을 검사
#   tools/leak-check.sh --tracked    추적 중인 파일 전체를 검사
#   tools/leak-check.sh FILE...      지정한 파일을 검사
#
# 문서용 대역(RFC 5737 / 3849 / 7042)과 tools/leak-allow.txt 의 값은 예외다.
# 발견되면 종료 코드 1.

set -u
cd "$(dirname "$0")/.." || exit 2
ALLOW=tools/leak-allow.txt

mode=${1:-staged}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
src=$tmp/input

case "$mode" in
  --tracked) git ls-files -z | xargs -0 -I{} sh -c 'printf "==FILE== %s\n" "$1"; cat "$1"' _ {} > "$src" ;;
  staged)
    # 추가되는 줄만 본다. 파일 경계를 표식으로 남긴다.
    git diff --cached --unified=0 | awk '
      /^\+\+\+ b\//{f=substr($0,7); printf "==FILE== %s\n", f; next}
      /^\+/ && !/^\+\+\+/{print substr($0,2)}' > "$src" ;;
  *) for f in "$@"; do printf '==FILE== %s\n' "$f"; cat "$f"; done > "$src" ;;
esac

[ -s "$src" ] || { echo "leak-check: 검사할 내용 없음"; exit 0; }

# 예외 값을 정규식 안전하게 이스케이프해 모은다
allow_re=$(grep -vE '^[[:space:]]*(#|$)' "$ALLOW" 2>/dev/null \
  | sed -E 's/[[:space:]]*#.*//; s/[[:space:]]+$//' | grep -v '^$' \
  | sed -E 's/[.[\*^$(){}|+?\\]/\\&/g' | paste -sd'|' -)
[ -n "$allow_re" ] || allow_re='\$\^NOMATCH'

hits=0
# report 종류 설명 패턴  [제외패턴]
report() {
  local kind=$1 desc=$2 pat=$3 excl=${4:-}
  local out
  # 제외 패턴은 대소문자를 구분한다. -i 를 주면 소문자 클래스가 대문자까지
  # 먹어서, 대문자로 시작하는 실제 토큰이 "그냥 식별자"로 빠져나간다.
  out=$(grep -nEo "$pat" "$src" 2>/dev/null | { [ -n "$excl" ] && grep -vE "$excl" || cat; } \
        | grep -vE ":(${allow_re})$" | sort -u -t: -k2 | head -20)
  [ -z "$out" ] && return 0
  hits=1
  printf '\n[%s] %s\n' "$kind" "$desc"
  # 줄 번호 → 파일 이름으로 되짚기
  while IFS=: read -r ln val; do
    local file
    file=$(awk -v n="$ln" '/^==FILE== /{f=substr($0,10)} NR==n{print f; exit}' "$src")
    printf '  %-22s  %s\n' "$val" "${file:-?}"
  done <<< "$out"
}

# --- IPv4: 문서용 대역 밖의 dotted quad
report IPV4 "문서용 대역(192.0.2/198.51.100/203.0.113) 밖 IPv4" \
  '\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b' \
  '(^|:)(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.)'

# --- MAC: RFC 7042 문서용(00:00:5e:00:53:xx) 밖
report MAC "문서용(00:00:5e:00:53:xx) 밖 MAC 주소" \
  '\b[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}\b' \
  ':00:00:5e:00:53:'

# --- IPv6: 2001:db8::/32 밖의 콜론 주소 (link-local 포함, MAC 파생 가능)
report IPV6 "문서용(2001:db8::/32) 밖 IPv6로 보이는 값" \
  '\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b' \
  ':(2001:[dD][bB]8|::1)|00:00:5[eE]:00:53|:[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$|:[0-9]{1,2}(:[0-9]{2}){1,2}$'

# --- 홈 경로 / 사용자명
report PATH "홈 경로 노출" '/Users/[A-Za-z0-9._-]+'
report EMAIL "이메일 주소" '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'

# --- 토큰형 긴 문자열
# 프로그램 식별자를 비밀로 오인하지 않는다. 제외 조건 두 가지:
#   전부 소문자 + 밑줄        함수·변수 이름 (긴 16진은 아래 HEX 규칙이 잡는다)
#   숫자도 base64 기호도 없음  kCLAuthorizationStatus... 같은 CamelCase 식별자
# 숫자가 하나도 없는 base64 비밀은 놓치지만, 실제 토큰은 거의 항상 숫자나
# +/= 를 포함한다. 매번 우는 검사기보다 낫다고 판단했다.
report TOKEN "토큰으로 보이는 긴 문자열(40자 이상)" \
  '\b[A-Za-z0-9_+/-]{40,}={0,2}' \
  ':[a-z][a-z0-9_-]*$|:[A-Za-z_./-]+$'
report HEX "16진 비밀로 보이는 값(32자 이상)" '\b[0-9a-f]{32,}\b'

# --- 호스트명 힌트
report HOST "호스트명으로 보이는 .local 이름" '\b[A-Za-z0-9-]+\.local\b'

if [ $hits -eq 0 ]; then
  echo "leak-check: 통과 — 식별자 패턴 없음"
  exit 0
fi
cat <<'MSG'

── 판정 방법 ──
  실제 환경 값이면 합성값으로 바꾼다:
    IPv4 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    IPv6 2001:db8::/32   MAC 00:00:5e:00:53:xx   도메인 example.com   SSID ExampleNet
  코드에 반드시 있어야 하는 무해한 상수면 사유와 함께 tools/leak-allow.txt 에 추가한다.
MSG
exit 1
