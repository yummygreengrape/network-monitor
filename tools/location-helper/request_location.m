// 위치 서비스 권한을 요청한다. 좌표는 읽지 않는다.
//
// Wi-Fi 이름(SSID)과 AP 식별자(BSSID)는 macOS 에서 위치 권한이 있어야 읽힌다.
// 권한이 없으면 <redacted> 로 가려진다. 이 도구가 필요로 하는 것은 그 두 값뿐이라
// startUpdatingLocation 을 호출하지 않는다 — 권한만 요청하고 끝낸다.
//
// 상태를 stdout 에 한 줄로 출력한다: status=<이름>
#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>

static const char *StatusName(CLAuthorizationStatus s) {
    switch (s) {
        case kCLAuthorizationStatusNotDetermined:       return "not-determined";
        case kCLAuthorizationStatusRestricted:          return "restricted";
        case kCLAuthorizationStatusDenied:              return "denied";
        case kCLAuthorizationStatusAuthorizedAlways:    return "authorized-always";
#if defined(kCLAuthorizationStatusAuthorizedWhenInUse)
        case kCLAuthorizationStatusAuthorizedWhenInUse: return "authorized-when-in-use";
#endif
        default:                                        return "unknown";
    }
}

static const char *gOutPath = NULL;

static void WriteOut(const char *text) {
    const char *path = gOutPath ? gOutPath : getenv("NETMON_LOC_OUT");
    if (!path) return;
    FILE *f = fopen(path, "w");
    if (!f) return;
    // 이미 "key=value\n" 꼴이면 그대로, 아니면 status= 로 감싼다
    if (strchr(text, '=')) fputs(text, f);
    else fprintf(f, "status=%s\n", text);
    fclose(f);
}

static int ExitFor(CLAuthorizationStatus s) {
    switch (s) {
        case kCLAuthorizationStatusAuthorizedAlways:
#if defined(kCLAuthorizationStatusAuthorizedWhenInUse)
        case kCLAuthorizationStatusAuthorizedWhenInUse:
#endif
            return 0;
        case kCLAuthorizationStatusDenied:     return 1;
        case kCLAuthorizationStatusRestricted: return 3;
        default:                               return 2;  // 미결정 또는 응답 없음
    }
}

static const char *BandName(CWChannelBand b) {
    switch (b) {
        case kCWChannelBand2GHz: return "2.4";
        case kCWChannelBand5GHz: return "5";
        default: break;
    }
    // 6GHz 는 SDK 버전에 따라 상수가 없을 수 있어 숫자로 판별한다.
    if ((int)b == 3) return "6";
    return "";
}

static int WidthMHz(CWChannelWidth w) {
    switch (w) {
        case kCWChannelWidth20MHz:  return 20;
        case kCWChannelWidth40MHz:  return 40;
        case kCWChannelWidth80MHz:  return 80;
        case kCWChannelWidth160MHz: return 160;
        default: return 0;
    }
}

// **자기 연결의 상태만 읽는다.** 위치 좌표는 요청하지도 읽지도 않고,
// 주변 AP 목록(scanForNetworks)도 건드리지 않는다 — 남의 네트워크는
// 필요 조건 밖이다. 채널·대역·신호는 내 링크의 속성이라 읽는다.
// 이게 없으면 밴드 전환(2.4↔5GHz)이 그냥 "로밍" 으로 보인다. 실제로
// 2026-09-17 10:58 에 5GHz 에서 2.4GHz 로 내려간 것을 놓쳤고,
// 그 뒤로 속도 상한이 1200 에서 144 Mbps 로 떨어진 채 몇 시간이 갔다.
static int PrintWifi(void) {
    CWInterface *iface = [[CWWiFiClient sharedWiFiClient] interface];
    if (!iface) {
        fprintf(stdout, "wifi=none\n");
        WriteOut("wifi=none");
        return 4;
    }
    NSString *ssid = iface.ssid;
    NSString *bssid = iface.bssid;
    CWChannel *ch = iface.wlanChannel;
    NSMutableString *line = [NSMutableString string];
    [line appendFormat:@"ssid=%@\n", ssid ?: @""];
    [line appendFormat:@"bssid=%@\n", bssid ?: @""];
    if (ch) {
        [line appendFormat:@"channel=%ld\n", (long)ch.channelNumber];
        [line appendFormat:@"band=%s\n", BandName(ch.channelBand)];
        [line appendFormat:@"width=%d\n", WidthMHz(ch.channelWidth)];
    }
    [line appendFormat:@"rssi=%ld\n", (long)iface.rssiValue];
    [line appendFormat:@"noise=%ld\n", (long)iface.noiseMeasurement];
    [line appendFormat:@"txrate=%.0f\n", iface.transmitRate];
    fputs(line.UTF8String, stdout);
    fflush(stdout);
    WriteOut(line.UTF8String);
    return (ssid.length || bssid.length) ? 0 : 5;
}

@interface Requester : NSObject <CLLocationManagerDelegate>
@property(nonatomic, strong) CLLocationManager *mgr;
@property(nonatomic, assign) BOOL settled;
@end

@implementation Requester

// 기록만 한다. 출력은 main 에서 한 번만 한다 — 두 곳에서 쓰면 --status 와
// 요청 경로가 서로 다른 답을 낸다.
- (void)changedTo:(CLAuthorizationStatus)status {
    if (status == kCLAuthorizationStatusNotDetermined) return;  // 아직 응답 전
    self.settled = YES;
    CFRunLoopStop(CFRunLoopGetCurrent());
}

- (void)locationManagerDidChangeAuthorization:(CLLocationManager *)manager {
    [self changedTo:manager.authorizationStatus];
}

// macOS 11 미만 대비
- (void)locationManager:(CLLocationManager *)manager
    didChangeAuthorizationStatus:(CLAuthorizationStatus)status {
    [self changedTo:status];
}

- (void)locationManager:(CLLocationManager *)manager didFailWithError:(NSError *)error {
    fprintf(stderr, "오류: %s\n", error.localizedDescription.UTF8String);
}
@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        double timeout = 60.0;
        BOOL statusOnly = NO;
        BOOL wifiMode = NO;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--status") == 0) statusOnly = YES;
            else if (strcmp(argv[i], "--wifi") == 0) wifiMode = YES;
            else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) timeout = atof(argv[++i]);
            else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) gOutPath = argv[++i];
        }

        if (wifiMode) return PrintWifi();

        if (![CLLocationManager locationServicesEnabled]) {
            fprintf(stdout, "status=services-off\n");
            WriteOut("services-off");
            return 3;
        }

        Requester *r = [Requester new];
        r.mgr = [CLLocationManager new];
        r.mgr.delegate = r;

        // 권한 상태는 델리게이트로 비동기 전달된다. 매니저를 만든 직후 읽으면
        // 이미 승인된 앱도 not-determined 로 보인다. 첫 콜백을 잠깐 기다린다.
        NSDate *settleBy = [NSDate dateWithTimeIntervalSinceNow:2.0];
        while (!r.settled && [settleBy timeIntervalSinceNow] > 0) {
            @autoreleasepool {
                [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                         beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
            }
        }

        CLAuthorizationStatus now = r.mgr.authorizationStatus;
        if (statusOnly || now != kCLAuthorizationStatusNotDetermined) {
            fprintf(stdout, "status=%s\n", StatusName(now));
            WriteOut(StatusName(now));
            return ExitFor(now);
        }

        fprintf(stderr, "권한 요청 중 — 창이 뜨면 허용을 누르세요 (최대 %.0f초)\n", timeout);
        [r.mgr requestWhenInUseAuthorization];

        // CFRunLoopRunInMode 는 입력 소스가 없으면 곧바로 반환한다.
        // 권한 응답은 델리게이트로 오므로 기한까지 짧게 끊어서 돌린다.
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
        while (!r.settled && [deadline timeIntervalSinceNow] > 0) {
            @autoreleasepool {
                [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                         beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
                if (r.mgr.authorizationStatus != kCLAuthorizationStatusNotDetermined) break;
            }
        }

        CLAuthorizationStatus final = r.mgr.authorizationStatus;
        fprintf(stdout, "status=%s\n", StatusName(final));
        WriteOut(StatusName(final));
        return ExitFor(final);
    }
}
