#!/bin/bash

# VAJRA Shakti Kavach - Multi-Platform Build Script
# Builds for iOS, Android, Windows, macOS, Linux

set -e

echo "🛡️  VAJRA Shakti Kavach - Multi-Platform Builder"
echo "=================================================="

PLATFORM=${1:-all}
VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

build_android() {
    echo -e "${YELLOW}Building Android APK...${NC}"
    cordova build android --release
    cp platforms/android/app/build/outputs/apk/release/*.apk "./dist/VAJRA-Shakti-Kavach-${VERSION}.apk"
    echo -e "${GREEN}✓ Android APK built: dist/VAJRA-Shakti-Kavach-${VERSION}.apk${NC}"
}

build_ios() {
    echo -e "${YELLOW}Building iOS IPA...${NC}"
    cordova build ios --release
    xcodebuild -exportArchive -archivePath platforms/ios/build/device/ -exportPath "./dist/" -exportOptionsPlist exportOptions.plist
    echo -e "${GREEN}✓ iOS IPA built: dist/VAJRA-Shakti-Kavach-${VERSION}.ipa${NC}"
}

build_windows() {
    echo -e "${YELLOW}Building Windows EXE...${NC}"
    npm run build-win
    echo -e "${GREEN}✓ Windows EXE built: dist/VAJRA Shakti Kavach-${VERSION}.exe${NC}"
}

build_macos() {
    echo -e "${YELLOW}Building macOS DMG...${NC}"
    npm run build-mac
    echo -e "${GREEN}✓ macOS DMG built: dist/VAJRA-Shakti-Kavach-${VERSION}.dmg${NC}"
}

build_linux() {
    echo -e "${YELLOW}Building Linux AppImage...${NC}"
    npm run build-linux
    echo -e "${GREEN}✓ Linux AppImage built: dist/VAJRA-Shakti-Kavach-${VERSION}.AppImage${NC}"
}

# Create dist directory
mkdir -p dist

case $PLATFORM in
    android)
        build_android
        ;;
    ios)
        build_ios
        ;;
    windows|win)
        build_windows
        ;;
    macos|mac)
        build_macos
        ;;
    linux)
        build_linux
        ;;
    all)
        echo -e "${YELLOW}Building for all platforms...${NC}"
        build_windows
        build_linux
        build_macos
        echo -e "${YELLOW}Note: Build iOS/Android on macOS/Linux respectively${NC}"
        ;;
    *)
        echo "Usage: $0 [android|ios|windows|macos|linux|all]"
        echo ""
        echo "Examples:"
        echo "  $0 windows    # Build Windows EXE"
        echo "  $0 android    # Build Android APK"
        echo "  $0 ios        # Build iOS IPA"
        echo "  $0 all        # Build all desktop platforms"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Build complete!${NC}"
echo -e "Find your builds in: ${YELLOW}./dist/${NC}"
