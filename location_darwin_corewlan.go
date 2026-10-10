//go:build darwin && corewlan

package onboard

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework CoreLocation
#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

// Kept alive for the lifetime of the process. CLLocationManager has to
// outlive the requestWhenInUseAuthorization call, otherwise the system
// drops the request before the user can respond.
static CLLocationManager *_lifx_loc_mgr = nil;

// lifx_request_location_access triggers the macOS Location Services prompt
// and pumps the run loop until the user responds (or timeout). The prompt
// only appears when the binary is in a signed .app bundle whose Info.plist
// declares NSLocationWhenInUseUsageDescription; otherwise the function
// returns immediately with kCLAuthorizationStatusNotDetermined.
//
// timeout_seconds bounds how long the call blocks waiting for the user.
static int lifx_request_location_access(int timeout_seconds) {
    @autoreleasepool {
        if (_lifx_loc_mgr == nil) {
            _lifx_loc_mgr = [[CLLocationManager alloc] init];
        }
        CLAuthorizationStatus status = [_lifx_loc_mgr authorizationStatus];
        if (status != kCLAuthorizationStatusNotDetermined) {
            return (int)status;
        }

        [_lifx_loc_mgr requestWhenInUseAuthorization];

        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:timeout_seconds];
        while ([_lifx_loc_mgr authorizationStatus] == kCLAuthorizationStatusNotDetermined &&
               [deadline timeIntervalSinceNow] > 0) {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
        return (int)[_lifx_loc_mgr authorizationStatus];
    }
}
*/
import "C"

import "runtime"

// RequestMacOSLocationAccess prompts the user for Location Services access
// on macOS. WiFi scans and the current network name are redacted without
// this grant. Call it once at startup before scanning (Onboard,
// BulkOnboard, or OnboardBySSID with a serial).
//
// For the grant to apply the process must:
//   - be an app bundle whose Info.plist declares
//     NSLocationWhenInUseUsageDescription, code-signed (ad-hoc is enough)
//   - have been launched by LaunchServices (Finder, Dock, `open`) — a
//     binary exec'd from a shell is attributed to the terminal
//
// scripts/bundle.sh and cmd/lifx-onboard/launch_darwin.go show how the CLI
// does this.
//
// The call blocks for up to 15 seconds waiting for the user to respond.
// When the user has previously granted or denied access, returns
// immediately with the cached status. When unsupported (non-darwin, or
// built without the `corewlan` tag), returns AuthStatusUnsupported.
func RequestMacOSLocationAccess() AuthStatus {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return AuthStatus(C.lifx_request_location_access(15))
}
