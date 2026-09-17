"""한국어 문구 카탈로그.

어투 규칙
  - 결과·상태를 알리는 문장은 **명사형으로 끝낸다** (~됨, ~함, ~없음, ~불가).
    "게이트웨이 왕복 시간이 112ms 로 크게 증가함 (평균 20ms)."
  - 사용자에게 묻는 말과 시키는 말은 그대로 둔다 ("~할까요?", "~하세요").
  - 원인을 단정하지 않는다. 관측은 단정하되 해석에는 "의심", "추정",
    "~일 수 있음"을 붙인다.

영어 카탈로그(en.py)와 **이름과 자리표시자가 정확히 같아야 한다.**
tests/test_messages.py 가 그것을 확인한다.
"""
from __future__ import annotations

# ─────────────────────────────────────────── 판정: 링크 계층 (L2)
GW_MAC_CHANGED = ("게이트웨이 MAC 변경됨. 같은 네트워크에 머문 상태에서 바뀐 것이라 "
                  "ARP 스푸핑 또는 접속점 교체 의심.")
GW_MAC_CHANGED_MOVED = "게이트웨이 MAC 변경됨. 같은 시점에 네트워크도 변경됨."
DUPLICATE_IP = "IP 충돌 감지됨 (Duplicate IP seen 카운터 %d회 증가)."
ARP_REPLY_SPIKE = "ARP 응답 수신량이 평소의 %.0f배로 증가 (%d건/주기, 평균 %.1f)."
SHARED_MAC = ("MAC 하나가 IP %d개를 동시 사용 중. ARP 스푸핑에서 나타나는 형태이나 "
              "라우터 대리 응답에서도 같은 형태로 나타남.")

# ─────────────────────────────────────────── 판정: DHCP
DHCP_SERVER_CHANGED = "같은 네트워크에서 DHCP 서버 변경됨. rogue DHCP 의 전형적 형태."
DHCP_SERVER_CHANGED_MOVED = "DHCP 서버 변경됨. 같은 시점에 네트워크도 변경됨."
DHCP_ROUTER_CHANGED = "DHCP 가 알리는 기본 라우터 변경됨."
DHCP_DNS_CHANGED = "DHCP 가 알리는 DNS 서버 변경됨. 이름 해석 가로채기의 첫 단계일 수 있음."
DHCP_LEASE_RENEWED = "DHCP 임대 재시작됨. 링크가 한 번 끊겼다 다시 붙었다는 뜻."
OWN_IP_CHANGED = "이 기기에 할당된 IP 변경됨."

# ─────────────────────────────────────────── 판정: DNS·프록시
RESOLVER_CHANGED = "시스템 DNS 리졸버 변경됨."
DNS_LOCAL_PROXY_ON = "DNS 가 로컬 프록시를 경유하기 시작함."
DNS_LOCAL_PROXY_OFF = "DNS 가 로컬 프록시를 더 이상 경유하지 않음."
PROXY_ENABLED = "프록시 켜짐 (%s). 트래픽이 제3자를 경유함."
PROXY_SETTINGS_CHANGED = "프록시 설정 변경됨."

# ─────────────────────────────────────────── 판정: 경로
DEFAULT_ROUTE_CHANGED = "IPv4 기본 경로 변경됨."
IPV6_DEFAULT_ROUTE_APPEARED = ("물리 인터페이스에 IPv6 기본 경로 생성됨. 같은 네트워크의 "
                               "누군가가 라우터 광고를 보냈을 수 있음 (rogue RA).")
IPV6_ROUTER_APPEARED = "이웃 표에 새 IPv6 라우터 출현 (%d개)."
MULTIPLE_DEFAULT_ROUTES = "IPv4 기본 경로 %d개. VPN 사용 시 정상적으로 나타나는 형태."

# ─────────────────────────────────────────── 판정: Wi-Fi
WIFI_SECURITY_DOWNGRADE = ("Wi-Fi 암호화 약화됨 (%s → %s). 같은 이름을 쓰는 약한 "
                           "접속점으로 유인됐을 수 있음.")
WIFI_SECURITY_CHANGED = "Wi-Fi 암호화 방식 변경됨 (%s → %s)."
EVIL_TWIN_CANDIDATE = ("같은 SSID 에서 접속점과 게이트웨이·DHCP 가 함께 변경됨. "
                       "정상 로밍에서는 보통 게이트웨이가 그대로 유지됨.")
WIFI_ROAM = "같은 SSID 안에서 접속점 변경됨 (로밍)."
WIFI_NETWORK_SWITCHED = "다른 Wi-Fi 네트워크로 이동함."
WIFI_LINK_CHANGED = "Wi-Fi 링크 상태 변경됨 (%s → %s)."

# ─────────────────────────────────────────── 판정: 연결 품질
GATEWAY_ICMP_SILENT = ("이 네트워크의 게이트웨이는 ICMP 무응답. ARP 는 정상이므로 장애 아님. "
                       "도달성 판정을 ARP 기준으로 전환함.")
GATEWAY_ICMP_OK = "게이트웨이 ICMP 응답 확인. 도달성과 지연을 ping 으로 판정함."
FIRST_HOP_UNREACHABLE = "첫 홉 연속 %d회 무응답 (%s 기준). 무선 구간 문제로 추정."
FIRST_HOP_RECOVERED = "첫 홉 응답 복구됨 (%d회 실패 후, %s 기준)."
LATENCY_SPIKE = "게이트웨이 왕복 시간이 %.0fms 로 크게 증가함 (평균 %.0fms)."
MEASUREMENT_GAP = "측정이 %.0f초 동안 중단됨 (잠자기 또는 프로세스 중단)."

# ─────────────────────────────────────────── 판정: VPN
VPN_DISCONNECTED = "%s 연결 끊김. 가장 유력한 설명: %s."
VPN_PROTECTION_LOST = ("%s 끊김으로 트래픽이 터널 밖으로 나감. 이 네트워크는 같은 L2 의 "
                       "다른 기기가 들여다볼 수 있는 곳.")
VPN_PROTECTION_LOST_UNKNOWN = "%s 끊김. 이 네트워크를 신뢰할 수 있는지는 판단 불가."
VPN_RECONNECTED = "%s 재연결됨%s."
VPN_STATE_CHANGED = "%s 상태 변경됨 (%s → %s)."
VPN_STATE_UNKNOWN = "%s 상태 확인 불가 (%s → %s)."
VPN_SINCE = " (%s 부터 끊김)"

# VPN 끊김의 "가장 유력한 설명"
WHY_USER = "사용자가 직접 끊음"
WHY_SLEEP = "잠자기"
WHY_MOVED = "네트워크 이동"
WHY_LINK = "첫 홉 무응답 — 무선 구간 문제"
WHY_TUNNEL = "첫 홉은 정상 — 터널 경로 문제"
WHY_UNKNOWN = "판단 근거 부족"

DETECTOR_ERROR = "판정기 %s 예외로 중단: %s"

# ─────────────────────────────────────────── 조사
INV_OPENED = "%s 때문에 조사 %s 시작. 결론이 날 때까지 계속 관측함."
INV_RETUNED = "조사 %s 기준 변경: %s"
INV_ABANDONED = "조사 %s 중단. 네트워크가 바뀌어 대상 소멸."
INV_COOLDOWN = ("%s 조사를 방금 종료함. %d주기 동안 같은 종류를 다시 열지 않음 "
                "(%s 신호는 기록에 남음).")
INV_BUDGET_SPENT = "[%s] %d주기 관측했으나 판별 실패. 관측만 남기고 종료함."
INV_ERROR = "조사 %s 예외로 중단: %s"
INV_ABANDON_REASON_NETWORK = "네트워크가 바뀌어 중단함"
INV_ABANDON_REASON_NO_PLAYBOOK = "조사 지침을 찾을 수 없음"
INV_ABANDON_REASON_ERROR = "조사 중 오류: %s"
INV_BUDGET_VERDICT = "예산 안에 결론이 나지 않음 (%d주기)"

# 조사 지침 — L2 정체
INV_L2_WIDEN = "MAC 변경에 경로·이름 해석 변화가 겹침. 감시 범위를 넓힘."
INV_L2_CORROBORATED = ("첫 홉의 정체가 바뀐 뒤 %s 가 함께 나타남. 접속점 교체만으로는 "
                       "설명되지 않음.")
INV_L2_CORROBORATED_VERDICT = "경로를 쥔 무언가가 바뀜 — 중간자 가능성"
INV_L2_FLAPPING = ("게이트웨이 MAC 이 %d번 변경됐고 서로 다른 값 %d개 관측됨. "
                   "정상적인 접속점 교체는 이렇게 되돌아가지 않음.")
INV_L2_FLAPPING_VERDICT = "첫 홉의 정체가 요동침"
INV_L2_STABLE = ("새 게이트웨이 MAC 이 %d주기 동안 유지되고 뒤따른 신호 없음. "
                 "접속점 교체로 추정. 공격 가능성을 배제하지는 못함.")
INV_L2_STABLE_VERDICT = "새 첫 홉으로 안정됨"

# 조사 지침 — 경로·이름 해석 설정
INV_PATH_CONTESTED = "설정이 반복해서 바뀜. 한 번의 변조가 아니라 경합으로 판단함."
INV_PATH_PERSISTED = "바뀐 경로·이름 해석 설정이 %d주기 동안 유지됨%s."
INV_PATH_CONTESTED_NOTE = " (그 전에 여러 번 흔들림)"
INV_PATH_VERDICT = "바뀐 설정이 자리 잡음"

# 조사 지침 — VPN 끊김
INV_VPN_WIDEN = "끊김이 되풀이됨. 무선 구간 품질도 함께 관측함."
INV_VPN_REPEATED = "%s 가 %d번 끊김. %s."
# 어느 구간이 문제였나. **"되풀이" 같은 틀을 여기 넣지 않는다** — 단발 결론에
# 그대로 쓰면 "한 번 끊겼다 … 되풀이되는 끊김" 같은 자기모순이 된다.
INV_VPN_LEG_TUNNEL = "끊길 때마다 첫 홉은 정상이었음 — 터널 쪽 문제"
INV_VPN_LEG_LINK = "끊길 때 무선 구간도 불안정했음"
INV_VPN_LEG_UNKNOWN = "구간 판별 실패"
INV_VPN_VERDICT_TUNNEL = "터널 쪽에서 되풀이되는 끊김"
INV_VPN_VERDICT_LINK = "무선 구간 불안정과 함께 되풀이되는 끊김"
INV_VPN_VERDICT_UNKNOWN = "되풀이되는 끊김 — 구간 판별 실패"

# 조사 기록에 남는 짧은 표시
INV_NOTE_START = "조사 시작"
INV_NOTE_RETUNE = "기준 변경"
INV_NOTE_MAC_AGAIN = "게이트웨이 MAC 재변경"
INV_NOTE_CORROBORATED = "다른 신호 동반 출현"
INV_NOTE_CONFIG_AGAIN = "설정 재변경"
INV_NOTE_DROP_AGAIN = "재차 끊김"
INV_NOTE_RECONNECT = "재연결"
INV_NOTE_LINK_EVENT = "같은 구간에 링크 사건"
INV_NOTE_SAME_SIGNAL = "같은 종류의 신호 재출현"

# ─────────────────────────────────────────── 보고서
CONF_CONFIRMED = "확정  — 관측만으로 사실 단정 가능"
CONF_SUSPECT = "의심  — 기준선과 불일치. 양성 오류 여지 있음"
CONF_POSSIBLE = "가능  — 구조적으로 가능. 증거 없음"
REPORT_HEADER = "== %s  관측 %d주기, 판정 %d건"
REPORT_EXPOSURE_TITLE = "-- 이 네트워크에서 구조적으로 가능한 것 (증거 없음) --"
REPORT_INVESTIGATION_TITLE = "-- 조사 --"
REPORT_INVESTIGATION_NOTE = "   유의미한 신호가 잡히면 결론이 날 때까지 계속 관측함."
REPORT_SUPPRESSED_TITLE = "-- 사용자 행동·환경으로 설명되어 억제된 판정 (%d건) --"
REPORT_SUPPRESSED_NOTE = "   삭제되지 않고 남음. 억제 판단이 틀렸다면 여기서 확인."
REPORT_NO_ACTIVE = "  활성 판정 없음."
REPORT_REDACTED = "-- 식별자를 가린 출력. %s --"

EXPOSURE_SHARED_PSK = ("공유 비밀번호 Wi-Fi(%s): 비밀번호를 아는 사람은 같은 L2 에 있으며 "
                       "ARP·DHCP·RA 조작과 수동 복호 가능.")
EXPOSURE_OPEN = "암호화 없는 Wi-Fi: 같은 공간의 누구나 평문 열람 가능."
EXPOSURE_DNS_PROXY = ("DNS 가 로컬 프록시를 경유함. VPN·필터의 정상 동작일 수도, "
                      "가로채기일 수도 있음 — 무엇이 듣고 있는지는 이 도구가 판별 불가.")

# ─────────────────────────────────────────── 실시간 화면
WATCH_AGENT_RUNNING = "에이전트 실행 중 (pid %s)"
WATCH_AGENT_WAITING = "에이전트 등록됨, 실행 대기"
WATCH_AGENT_NONE = "상시 실행 등록 안 됨"
WATCH_NO_SAMPLES = "아직 기록 없음"
WATCH_STALE = " ← 갱신 중단됨"
WATCH_SUMMARY = "관측 %d주기, 마지막 %s"
WATCH_WIRED = "유선"
WATCH_DNS_PROXY = "DNS 로컬 프록시"
WATCH_SECTION_INVESTIGATION = "조사"
WATCH_SECTION_FINDINGS = "최근 판정"
WATCH_NO_INVESTIGATION = "열린 조사 없음"
WATCH_NO_FINDINGS = "아직 판정 없음"
WATCH_INV_LINE = "%s  %d주기  계기=%s"
WATCH_INV_RETUNED = "기준 %d번 변경 — 마지막: %s"
WATCH_RULES = "기준: %s"
WATCH_FOOTER = "Ctrl+C 로 닫기. 창을 닫아도 감시는 계속됨."
WATCH_SUPPRESSED_TAG = "억제"

# ─────────────────────────────────────────── 설정 마법사
WZ_TITLE = "netmon 초기 설정"
WZ_INTRO = ("엔터만 누르면 기본값입니다. 기본값은 sudo 를 쓰지 않고, 외부로\n"
            "요청을 보내지 않고, 상시 실행으로 등록하지도 않습니다.")
WZ_PICK = "선택 [%d]: "
WZ_PICK_RANGE = "  1에서 %d 사이의 번호를 넣으세요."
WZ_YES_NO = "  y 또는 n 으로 답하세요."
WZ_DEFAULT_MARK = " (기본)"

WZ_LANG_Q = "어떤 언어로 표시할까요? / Which language should netmon use?"
WZ_LANG_KO = "한국어"
WZ_LANG_EN = "English"

WZ_INTERVAL_Q = "얼마나 자주 측정할까요?"
WZ_INTERVAL_3 = "변화를 빨리 잡습니다. 배터리를 조금 더 씁니다"
WZ_INTERVAL_5 = "대부분의 경우에 적당합니다"
WZ_INTERVAL_10 = "배터리를 아낍니다. 짧은 끊김을 놓칠 수 있습니다"
WZ_INTERVAL_30 = "아주 가볍게. 품질 판정은 거칠어집니다"

WZ_LOGDIR_Q = "\n기록을 어디에 둘까요?"
WZ_RETENTION_Q = "기록을 며칠 보관할까요?"
WZ_RETENTION_7 = "가볍게"
WZ_RETENTION_14 = "기본"
WZ_RETENTION_30 = "오래 되짚어 보려면"
WZ_RETENTION_90 = "디스크를 꽤 씁니다"

WZ_LOCATION_HEAD = "[위치 권한]  Wi-Fi 이름(SSID)과 접속점 식별자(BSSID)를 읽습니다."
WZ_LOCATION_BODY = ("  같은 이름을 쓰는 가짜 접속점(evil twin)과 정상적인 접속점 전환을\n"
                    "  구분하는 데 씁니다. 위치 좌표는 읽지 않고, 값은 이 기기 밖으로\n"
                    "  나가지 않습니다. macOS 권한이 앱 단위라 작은 헬퍼 앱을 만듭니다.")
WZ_LOCATION_Q = "  위치 권한을 쓸까요?"

WZ_VPN_HEAD = "[VPN 감시]  이 기기에서 찾은 VPN: %s"
WZ_VPN_BODY = "  연결 상태와 끊김을 함께 기록합니다. 외부로 나가는 요청은 없습니다."
WZ_VPN_Q = "  VPN 감시를 켤까요?"
WZ_VPN_NONE = "[VPN 감시]  설치된 VPN 을 찾지 못해 건너뜁니다."

WZ_EXTERNAL_HEAD = "[외부 점검 요청]  DNS 응답을 기준값과 비교하고(가로채기 탐지),"
WZ_EXTERNAL_BODY = ("  고정 호스트의 TLS 발급자와 공인 IP 변화를 봅니다.\n"
                    "  고정된 조회 이름과 이 기기의 출발지 IP 가 밖으로 나갑니다.\n"
                    "  SSID·BSSID·MAC 같은 네트워크 식별자는 보내지 않습니다.")
WZ_EXTERNAL_Q = "  외부 점검 요청을 켤까요?"

WZ_AGENT_HEAD = "[상시 실행]  로그인할 때 자동으로 시작하고, 멈추면 다시 띄웁니다."
WZ_AGENT_BODY = ("  ~/Library/LaunchAgents 에 파일 하나를 만듭니다. sudo 는 쓰지 않고,\n"
                 "  나중에 netmon service uninstall 로 되돌릴 수 있습니다.")
WZ_AGENT_Q = "  항상 켜 둘까요?"

WZ_LINK_HEAD = "[명령 등록]  지금은 저장소 안에서 ./netmon.sh 로만 실행됩니다."
WZ_LINK_BODY = ("  다른 디렉터리에서 치면 셸이 파일을 찾지 못합니다. PATH 에 있는\n"
                "  디렉터리에 링크를 걸어 두면 어디서나 netmon 으로 실행됩니다.\n"
                "  sudo 는 쓰지 않고, netmon link remove 로 되돌립니다.")
WZ_LINK_Q = "  어디서나 netmon 으로 실행할까요?"

WZ_SUMMARY_HEAD = "이대로 적용합니다:"
WZ_CONFIRM_Q = "\n적용할까요?"
WZ_ROW_LANGUAGE = "언어             %s"
WZ_ROW_INTERVAL = "측정 간격        %d초"
WZ_ROW_LOGDIR = "기록 위치        %s"
WZ_ROW_RETENTION = "보존 기간        %d일"
WZ_ROW_LOCATION = "위치 권한        %s  (evil twin 탐지)"
WZ_ROW_VPN = "VPN 감시         %s  (%s)"
WZ_ROW_EXTERNAL = "외부 점검 요청   %s  (DNS·TLS 가로채기, 공인 IP)"
WZ_ROW_AGENT = "상시 실행        %s  (로그인할 때 자동 시작)"
WZ_ROW_LINK = "명령 등록        %s  (어디서나 netmon 으로 실행)"
WZ_ON = "켬"
WZ_OFF = "끔"

# ─────────────────────────────────────────── CLI 공통
CLI_NO_FINDINGS = "  판정 없음"
CLI_COLLECT_FAILED = "  수집 실패 %s: %s"
CLI_RUN_START = "측정을 시작합니다 — 간격 %d초, 기록 %s  (Ctrl+C 로 종료)"
CLI_RUN_DONE = "%d주기를 기록했습니다 → %s"
CLI_RUN_FASTER = "%s  조사 %d건 진행 중 — 측정 간격을 %.0f초로 줄입니다"
CLI_NO_RECORDS = "%s 기록이 없습니다 (%s)"
CLI_CAPTURE_START = "관측 %d주기를 %s 로 저장합니다 (간격 %d초)%s"
CLI_CAPTURE_REDACT = ", 식별자 가림"
CLI_CAPTURE_DONE = "저장했습니다 → %s"
CLI_REPLAY_START = "%d주기를 재생합니다 — %s"
CLI_REPLAY_DONE = "판정 %d건"
CLI_DOCTOR_CONFIG = "설정   %s"
CLI_DOCTOR_LANG = "언어   %s (%s)"
CLI_DOCTOR_DATA = "데이터 %s"
CLI_LANG_CURRENT = "지금 언어  %s (%s)"
CLI_LANG_CONFIG = "설정 파일  %s"
CLI_LANG_ENV = "환경 변수  %s=%s  (설정 파일보다 우선)"
CLI_LANG_AVAILABLE = "쓸 수 있는 언어:"
CLI_LANG_HOWTO = "바꾸기:  netmon lang en"
CLI_LANG_FILES = "문구 파일: netmon/messages/<코드>.py"
CLI_LANG_UNKNOWN = "모르는 언어 코드: %s (쓸 수 있는 것: %s)"
CLI_LANG_CHANGED = "언어를 %s (%s) 로 바꿨습니다 → %s"
CLI_LANG_KEEPS_RECORDS = "이미 기록된 판정의 문구는 그대로입니다. 기록은 사후에 바꾸지 않습니다."
CLI_LINK_DONE = "이제 어디서나 `netmon` 으로 실행할 수 있습니다."
CLI_LINK_PATH = "  링크  %s"
CLI_LINK_TARGET = "  대상  %s"
CLI_LINK_NOT_ON_PATH = ("다만 이 디렉터리는 PATH 에 없습니다. 아래 한 줄을 실행한 뒤\n"
                        "터미널을 새로 열면 `netmon` 이 바로 잡힙니다:")
CLI_LINK_NONE = "PATH 에 netmon 링크가 없습니다."
CLI_LINK_USE_REPO = "저장소 안에서는 ./netmon.sh 로 실행합니다:"
CLI_LINK_HOWTO = "어디서나 쓰려면: netmon link"
CLI_LINK_OTHER_REPO = "  ← 다른 저장소를 가리킵니다"
CLI_LINK_REMOVED = "지웠습니다: %s"
CLI_LINK_SKIPPED = "건너뛰었습니다(링크가 아님): %s"
CLI_LINK_NOTHING = "지울 링크가 없습니다."
CLI_LINK_WHERE = "링크를 걸 곳: %s (%s)"
CLI_LINK_NO_DIR = "링크를 걸 만한 디렉터리를 찾지 못했습니다. --dir 로 지정해 주세요."
CLI_SETUP_SAVED = "설정을 저장했습니다 → %s"
CLI_SETUP_CANCELLED = "취소했습니다. 아무것도 바꾸지 않았습니다."
CLI_SETUP_DONE = "설정을 마쳤습니다. 확인:  %s doctor"
CLI_SETUP_NEXT_RUN = "측정 시작:     %s run"
CLI_SETUP_BUILD_HELPER = "위치 권한 헬퍼를 만듭니다..."
CLI_SETUP_NO_LOCATION = "위치 권한을 받지 못했습니다. 나머지 탐지는 그대로 동작합니다."
CLI_AGENT_INTRO = ("로그인할 때 자동으로 시작하고, 멈추면 다시 띄웁니다.\n"
                   "~/Library/LaunchAgents 에 파일 하나를 만듭니다. sudo 는 쓰지 않습니다.")
CLI_AGENT_DONE = "상시 실행으로 등록했습니다."
CLI_AGENT_FAILED = "등록에 실패했습니다: %s"
CLI_AGENT_REMOVED = "해제했습니다."
CLI_AGENT_NOT_INSTALLED = "등록되어 있지 않았습니다."
CLI_AGENT_RECORDS_KEPT = "기록은 %s 에 그대로 남아 있습니다."

# ─────────────────────────────────────────── 로그 실측으로 드러난 항목
ARP_REPLY_SPIKE_RATE = "ARP 응답 수신이 초당 %.1f건으로 증가 (평소 %.1f건)."
LATENCY_SPIKE_SUSTAINED = "게이트웨이 왕복 시간이 %.0fms 로 크게 증가함 (평균 %.0fms, %d주기 연속)."
INV_L2_NO_CHANGE = "첫 홉의 정체는 %d주기 동안 그대로 유지됨. 스푸핑 흔적 없음."
INV_L2_NO_CHANGE_VERDICT = "첫 홉 정체 변화 없음"

# ─────────────────────────────────────────── WARP 끊김 로그에서 드러난 항목
INV_VPN_SETTLED = "%s 가 %d번 끊겼다가 복구된 뒤 %d주기 동안 안정적임. %s."
INV_VPN_VERDICT_SETTLED = "끊긴 뒤 복구되어 안정됨 (%d회)"

# ─────────────────────────────────────────── 네트워크 정체성 모호성
EXPOSURE_IDENTITY_AMBIGUOUS = (
    "위치 권한이 없어 SSID 를 읽지 못함. 같은 사설 대역(예: 192.168.0.0/24)을 쓰는 "
    "다른 장소를 구분하지 못하므로, 장소를 옮기면 첫 홉 변경이 이동인지 공격인지 "
    "가리기 어려움.")

# ─────────────────────────────────────────── 불완전한 관측
LINK_ABSENT = "주 인터페이스가 없어 이 주기는 판정하지 않음. 링크가 끊긴 상태."
WHY_LINK_GONE = "링크 자체가 사라짐"

# ─────────────────────────────────────────── 날짜 기준
DAY_IS_UTC = "날짜는 UTC 기준입니다 (현지 %s)."
WHY_WOKE = "잠자기에서 깨어나는 중"
WHY_LINK_BACK = "링크가 막 다시 붙음"

# ─────────────────────────────────────────── 암호화 방식별 노출
EXPOSURE_SHARED_SAE = ("WPA3-SAE Wi-Fi(%s): 비밀번호를 아는 사람은 같은 L2 에 들어올 수 있어 "
                       "ARP·DHCP·RA 조작이 가능함. 다만 세션마다 키가 달라 비밀번호를 "
                       "알아도 남의 트래픽을 수동으로 복호하지는 못함.")
VPN_PROTECTION_LOST_SAE = ("%s 끊김으로 트래픽이 터널 밖으로 나감. WPA3-SAE 라 조용히 읽히지는 "
                           "않지만, 같은 L2 에 들어온 기기가 경로를 가로채면 볼 수 있음.")
