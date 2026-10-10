#!/usr/bin/env bash
#
# Builds the lifx-onboard CLI as an ad-hoc signed .app bundle.
#
# Background: on macOS, WiFi scan results (auto / bulk / scan with the
# corewlan scanner) are redacted unless the process has Location Services,
# and that grant is keyed to a code-signed bundle identity. The `ssid`
# command does not scan and does not need the bundle.
#
# Usage:
#
#   scripts/bundle.sh                  # builds build/LifxOnboard.app (corewlan)
#   TAGS= scripts/bundle.sh            # build without the corewlan cgo scanner
#   build/LifxOnboard.app/Contents/MacOS/lifx-onboard ssid "LIFX A19 228447" --home-ssid MyNet
#
# The first network access triggers the Local Network prompt (and, for
# auto/bulk/scan with corewlan, the Location Services prompt) — click
# Allow. Rebuilding into the same bundle keeps the grants.

set -euo pipefail

APP_NAME="LifxOnboard"
EXE_NAME="lifx-onboard"
TAGS="${TAGS-corewlan}"
MODULE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLE_DIR="${MODULE_ROOT}/build/${APP_NAME}.app"
EXE_PATH="${BUNDLE_DIR}/Contents/MacOS/${EXE_NAME}"

rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}/Contents/MacOS"

cat > "${BUNDLE_DIR}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>${EXE_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>dev.lifx-onboard.cli</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>Connect to a LIFX device in SoftAP mode at 172.16.0.1 to deliver home WiFi credentials, then find it on the home network.</string>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>The list of nearby WiFi networks is needed to locate LIFX SoftAP devices during onboarding.</string>
</dict>
</plist>
EOF

cd "${MODULE_ROOT}"
go build -tags "${TAGS}" -o "${EXE_PATH}" ./cmd/lifx-onboard

codesign --force --deep --sign - "${BUNDLE_DIR}"

cat <<EOF

Built ${BUNDLE_DIR}

Run it directly from the bundle:
  ${EXE_PATH} ssid "LIFX A19 228447" --home-ssid MyNet

Or put it on your PATH:
  ln -sf "${EXE_PATH}" /usr/local/bin/${EXE_NAME}

The first run triggers the macOS Local Network prompt — click Allow.
EOF
