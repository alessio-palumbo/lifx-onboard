#!/usr/bin/env bash
#
# Builds the lifx-onboard CLI as a signed macOS app bundle, build/LifxOnboard.app.
#
# macOS only reveals WiFi network names to a process that LaunchServices
# launched as an app and that has Location Services; the CLI relaunches
# itself through this bundle to get there. See the README's macOS section.
#
# Usage:
#
#   scripts/bundle.sh                         # host architecture, ad-hoc signed
#   ARCHS="arm64 amd64" scripts/bundle.sh     # universal binary
#
# Environment:
#
#   ARCHS          Go architectures to build (default: host); several → lipo'd
#   VERSION        version string, e.g. v0.2.0 (default: dev)
#   SIGN_IDENTITY  codesign identity (default: "-", ad-hoc). A Developer ID
#                  identity also enables the hardened runtime, as required
#                  for notarization.
#   TAGS           Go build tags (default: corewlan)
#   OUT_DIR        output directory (default: build)

set -euo pipefail

APP_NAME="LifxOnboard"
EXE_NAME="lifx-onboard"
BUNDLE_ID="com.alessiopalumbo.lifx-onboard"
MODULE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ARCHS="${ARCHS:-$(go env GOARCH)}"
VERSION="${VERSION:-dev}"
SIGN_IDENTITY="${SIGN_IDENTITY:--}"
TAGS="${TAGS-corewlan}"
OUT_DIR="${OUT_DIR:-${MODULE_ROOT}/build}"

BUNDLE_DIR="${OUT_DIR}/${APP_NAME}.app"
EXE_PATH="${BUNDLE_DIR}/Contents/MacOS/${EXE_NAME}"
ENTITLEMENTS="${MODULE_ROOT}/scripts/entitlements.plist"

# CFBundleShortVersionString must be numeric: v0.2.0 → 0.2.0, dev → 0.0.0.
SHORT_VERSION="${VERSION#v}"
[[ "$SHORT_VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]] || SHORT_VERSION="0.0.0"

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
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${SHORT_VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${SHORT_VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>Connect to a LIFX light in setup mode to give it your WiFi details, then find it on your network.</string>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>macOS requires Location access to list nearby WiFi networks, which is how lifx-onboard finds LIFX lights in setup mode.</string>
</dict>
</plist>
EOF

cd "${MODULE_ROOT}"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
slices=()
for arch in ${ARCHS}; do
  CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" go build \
    -trimpath -tags "${TAGS}" \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${build_dir}/${EXE_NAME}-${arch}" ./cmd/lifx-onboard
  slices+=("${build_dir}/${EXE_NAME}-${arch}")
done
if (( ${#slices[@]} > 1 )); then
  lipo -create -output "${EXE_PATH}" "${slices[@]}"
else
  cp "${slices[0]}" "${EXE_PATH}"
fi

if [[ "${SIGN_IDENTITY}" == "-" ]]; then
  codesign --force --sign - --entitlements "${ENTITLEMENTS}" "${BUNDLE_DIR}"
else
  codesign --force --options runtime --timestamp \
    --entitlements "${ENTITLEMENTS}" \
    --sign "${SIGN_IDENTITY}" "${BUNDLE_DIR}"
fi
codesign --verify --strict --verbose=2 "${BUNDLE_DIR}"

cat <<EOF

Built ${BUNDLE_DIR} (${ARCHS}, ${VERSION})

Run it from the bundle, or put it on your PATH:
  ln -sf "${EXE_PATH}" /usr/local/bin/${EXE_NAME}

On first use allow LifxOnboard when macOS asks for Location access.
EOF
