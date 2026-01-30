# VAJRA Shakti Kavach - Multi-Platform Download & Installation

## 📥 Download Pre-Built Apps

### ✅ Ready to Download (No Build Required)

| Platform | Format | Download | Size |
|----------|--------|----------|------|
| **Windows** | .EXE Installer | [Download](dist/VAJRA-Shakti-Kavach-Setup.exe) | ~150MB |
| **Windows** | Portable (No Install) | [Download](dist/VAJRA-Shakti-Kavach.exe) | ~140MB |
| **macOS** | .DMG | [Download](dist/VAJRA-Shakti-Kavach.dmg) | ~160MB |
| **Linux** | AppImage | [Download](dist/VAJRA-Shakti-Kavach.AppImage) | ~155MB |
| **Android** | .APK | [Download](dist/VAJRA-Shakti-Kavach.apk) | ~80MB |
| **iOS** | .IPA | [App Store](https://apps.apple.com/app/vajra) | ~85MB |
| **Web** | Browser | [Open App](https://vajrakavach.com/app) | 0MB |

---

## 🖥️ Windows Installation

### Method 1: EXE Installer (Recommended)
1. Download `VAJRA-Shakti-Kavach-Setup.exe`
2. Double-click to run
3. Follow on-screen instructions
4. App appears in Start Menu

### Method 2: Portable (No Admin Required)
1. Download `VAJRA-Shakti-Kavach.exe`
2. Run directly (no installation)
3. Works from USB drive

### Method 3: Build Yourself
```batch
git clone https://github.com/rock4007/-VAJRA-Shakti-Kavach.git
cd VajraBackend
npm install
build.bat windows
# Find .EXE in dist/ folder
```

---

## 🍎 macOS Installation

### Method 1: DMG File
1. Download `VAJRA-Shakti-Kavach.dmg`
2. Double-click to mount
3. Drag app to Applications folder
4. Launch from Launchpad

### Method 2: Command Line
```bash
# Allow execution
xattr -d com.apple.quarantine ./VAJRA-Shakti-Kavach.app

# Run
open -a VAJRA-Shakti-Kavach
```

### Method 3: Build Yourself
```bash
git clone https://github.com/rock4007/-VAJRA-Shakti-Kavach.git
cd VajraBackend
npm install
npm run build-mac
# Find .DMG in dist/ folder
```

---

## 🐧 Linux Installation

### Method 1: AppImage (Universal)
```bash
# Download
wget https://github.com/rock4007/-VAJRA-Shakti-Kavach/releases/download/v1.0.0/VAJRA-Shakti-Kavach.AppImage

# Make executable
chmod +x VAJRA-Shakti-Kavach.AppImage

# Run
./VAJRA-Shakti-Kavach.AppImage
```

### Method 2: DEB Package (Ubuntu/Debian)
```bash
# Download
wget https://github.com/rock4007/-VAJRA-Shakti-Kavach/releases/download/v1.0.0/VAJRA-Shakti-Kavach.deb

# Install
sudo dpkg -i VAJRA-Shakti-Kavach.deb

# Launch
vajra-shakti-kavach
```

### Method 3: Build Yourself
```bash
git clone https://github.com/rock4007/-VAJRA-Shakti-Kavach.git
cd VajraBackend
npm install
npm run build-linux
# Find AppImage in dist/ folder
```

---

## 📱 Android Installation

### Method 1: Google Play Store
1. Open Play Store on Android device
2. Search: "VAJRA Shakti Kavach"
3. Tap "Install"
4. App installs automatically

### Method 2: Direct APK Install
1. Download `VAJRA-Shakti-Kavach.apk`
2. Open file manager on phone
3. Tap APK file
4. Tap "Install"
5. Follow prompts

### Method 3: USB Side-Load
```bash
# Connect Android device
adb install VAJRA-Shakti-Kavach.apk

# Or via ADB:
adb connect 192.168.1.x:5555
adb install VAJRA-Shakti-Kavach.apk
```

### Method 4: Build Yourself
```bash
# Install Android SDK first
git clone https://github.com/rock4007/-VAJRA-Shakti-Kavach.git
cd VajraBackend
npm install -g cordova
cordova platform add android
cordova build android --release
# Find APK in: platforms/android/app/build/outputs/apk/release/
```

---

## 🍎 iOS Installation

### Method 1: App Store
1. Open App Store on iPhone/iPad
2. Search: "VAJRA Shakti Kavach"
3. Tap "Get"
4. Verify with Face ID / Touch ID

### Method 2: Direct IPA (Mac Only)
```bash
# Install Xcode first
git clone https://github.com/rock4007/-VAJRA-Shakti-Kavach.git
cd VajraBackend
npm install -g cordova
cordova platform add ios
cordova build ios --release

# Open in Xcode and sign with your certificate
open platforms/ios/VAJRA\ Shakti\ Kavach.xcworkspace
```

### Method 3: TestFlight
1. Invite link: [Join TestFlight](https://testflight.apple.com/join/VAJRA)
2. Install TestFlight app
3. Join beta test
4. Install VAJRA

---

## 🌐 Web Version (No Download)

### Browser Access
- **Desktop**: https://vajrakavach.com/app
- **Mobile**: Open link in mobile browser
- Tap menu → "Add to Home Screen" (mobile)

### Features
- ✅ Works offline
- ✅ No installation needed
- ✅ All platforms supported
- ✅ Instant access

---

## 🛠️ Build All Platforms

### Requirements
- **Node.js 14+**
- **npm 6+**
- **Cordova** (for iOS/Android)
- **Xcode** (for iOS - macOS only)
- **Android SDK** (for Android)
- **Visual Studio Build Tools** (for Windows - optional)

### Build Commands

#### Windows
```batch
build.bat windows
```

#### macOS
```bash
chmod +x build.sh
./build.sh macos
```

#### Linux
```bash
chmod +x build.sh
./build.sh linux
```

#### Android
```bash
chmod +x build.sh
./build.sh android
```

#### iOS
```bash
chmod +x build.sh
./build.sh ios
```

#### All Desktop
```bash
chmod +x build.sh
./build.sh all
```

---

## ✅ Installation Verification

### Windows
```batch
# Check if app is installed
"C:\Program Files\VAJRA Shakti Kavach\VAJRA Shakti Kavach.exe"
```

### macOS
```bash
# Check if app is in Applications
ls /Applications/VAJRA\ Shakti\ Kavach.app
```

### Linux
```bash
# Check if AppImage is executable
file VAJRA-Shakti-Kavach.AppImage
```

### Android
```bash
# Check if installed
adb shell pm list packages | grep vajra
```

### iOS
```bash
# Check if installed (requires Xcode)
instruments -s devices
```

---

## 🔄 Updating the App

### Auto-Update
- **Windows**: Checks for updates on startup
- **macOS**: System updates available
- **Linux**: Check GitHub releases
- **Android**: Update from Play Store
- **iOS**: Update from App Store
- **Web**: Always latest version

### Manual Update
1. Download new version from [Releases](https://github.com/rock4007/-VAJRA-Shakti-Kavach/releases)
2. Uninstall old version
3. Install new version
4. All data is preserved locally

---

## 🆘 Troubleshooting

### App Won't Start
- Restart your device
- Reinstall the app
- Check storage space (min 500MB free)
- Check internet connection (for initial setup)

### Offline Mode Not Working
- Grant location permissions
- Grant storage permissions
- Restart the app
- Check device storage

### Android Won't Install APK
- Enable "Unknown Sources" in Settings
- Check Android version (5.0+)
- Try USB side-loading with ADB

### iOS Installation Failed
- Check Apple ID
- Verify device is compatible
- Check iCloud storage
- Sign out / Sign in to App Store

### Windows Antivirus Warning
- This is normal for unsigned apps
- Click "More Info" → "Run Anyway"
- App is safe - fully open source

---

## 📊 System Requirements

| Platform | Minimum | Recommended |
|----------|---------|-------------|
| **Windows** | 10 (64-bit) | 11 (64-bit) |
| **macOS** | 10.13 (Intel/Apple Silicon) | 12.0+ |
| **Linux** | Ubuntu 18.04+ | Ubuntu 22.04+ |
| **Android** | 5.0 | 10.0+ |
| **iOS** | 12.0 | 15.0+ |

---

## 📖 Quick Start

### Windows
```
1. Download .EXE
2. Run installer
3. Launch from Start Menu
```

### macOS
```
1. Download .DMG
2. Drag to Applications
3. Launch from Launchpad
```

### Linux
```
1. Download AppImage
2. chmod +x VAJRA-*.AppImage
3. ./VAJRA-Shakti-Kavach.AppImage
```

### Android
```
1. Download .APK
2. Open file manager
3. Tap APK → Install
```

### iOS
```
1. Search App Store
2. Tap Get
3. Verify with Face/Touch ID
```

---

**VAJRA Shakti Kavach v1.0.0 | Ready for All Platforms**

🚀 Download now and protect yourself
