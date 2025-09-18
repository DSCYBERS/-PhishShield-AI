@echo off
echo ========================================
echo PhishShield AI - Smart APK Builder
echo ========================================
echo.

echo 🔍 Checking build requirements...
echo.

REM Check Java installation
echo Checking Java...
java -version >nul 2>&1
if errorlevel 1 (
    echo ❌ Java not found
    echo.
    echo 📦 Installing Java automatically...
    winget install Microsoft.OpenJDK.17 --accept-source-agreements --accept-package-agreements
    
    echo.
    echo ⏳ Please restart this script after Java installation completes
    echo   (The installation window will close when finished)
    pause
    exit /b 1
) else (
    echo ✅ Java found!
)

echo.
echo Checking Android SDK...
if exist "%LOCALAPPDATA%\Android\Sdk" (
    echo ✅ Android SDK found at %LOCALAPPDATA%\Android\Sdk
    set ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk
) else if exist "%PROGRAMFILES%\Android\Android Studio" (
    echo ✅ Android Studio found
) else (
    echo ❌ Android SDK/Studio not found
    echo.
    echo 🌐 Opening Android Studio download page...
    start https://developer.android.com/studio
    echo.
    echo 📋 Please install Android Studio, then restart this script
    pause
    exit /b 1
)

echo.
echo ========================================
echo 🏗️ Building PhishShield AI APK
echo ========================================
echo.

echo Cleaning previous builds...
if exist app\build rmdir /s /q app\build 2>nul
if exist .gradle rmdir /s /q .gradle 2>nul

echo.
echo Starting Gradle build...
echo This may take 5-10 minutes on first build...
echo.

REM Try gradlew first
if exist gradlew.bat (
    echo Using Gradle Wrapper...
    call gradlew.bat assembleDebug --stacktrace
) else (
    echo ❌ gradlew.bat not found!
    echo Please ensure you're in the correct project directory
    pause
    exit /b 1
)

echo.
echo ========================================
echo 🔍 Checking Build Results
echo ========================================

if exist "app\build\outputs\apk\debug\app-debug.apk" (
    echo.
    echo 🎉 SUCCESS! APK Built Successfully!
    echo ========================================
    echo.
    echo 📱 APK Location: app\build\outputs\apk\debug\app-debug.apk
    echo.
    for %%A in ("app\build\outputs\apk\debug\app-debug.apk") do (
        echo 📊 File Size: %%~zA bytes (approx. %%~zA MB)
    )
    echo.
    echo 🚀 Ready for Installation!
    echo.
    echo ========================================
    echo 📋 Next Steps:
    echo ========================================
    echo.
    echo 1. 📱 Install on Android Device:
    echo    adb install app\build\outputs\apk\debug\app-debug.apk
    echo.
    echo 2. 📤 Share with Others:
    echo    Upload the APK to Google Drive, Dropbox, or file sharing service
    echo.
    echo 3. 🌐 Create Download Page:
    echo    Use the template in QUICK_LAUNCH.md
    echo.
    echo 4. 🎯 Test Core Features:
    echo    - Real-time URL scanning
    echo    - VPN protection toggle  
    echo    - Analytics dashboard
    echo    - Settings configuration
    echo.
    echo 🎊 PhishShield AI is ready to protect users!
    echo.
    
    REM Open the APK folder
    explorer "app\build\outputs\apk\debug\"
    
) else (
    echo.
    echo ❌ BUILD FAILED!
    echo ========================================
    echo.
    echo 🔍 Common Issues & Solutions:
    echo.
    echo 1. ☕ Java Issues:
    echo    - Restart PowerShell after Java installation
    echo    - Verify: java -version
    echo.
    echo 2. 📱 Android SDK Issues:
    echo    - Install Android Studio completely
    echo    - Accept all SDK licenses
    echo.
    echo 3. 🔄 Gradle Issues:
    echo    - Try: gradlew clean assembleDebug
    echo    - Check internet connection
    echo.
    echo 4. 💾 Storage Issues:
    echo    - Ensure 2GB+ free space
    echo    - Close other applications
    echo.
    echo 📞 Check the build log above for specific error details
    echo.
)

echo.
echo Press any key to continue...
pause >nul