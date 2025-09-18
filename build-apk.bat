@echo off
echo Building PhishShield AI APK...
echo.

REM Navigate to project directory
cd /d "c:\Users\Student\Downloads\project ew"

REM Clean previous builds
echo Cleaning previous builds...
if exist app\build rmdir /s /q app\build
if exist .gradle rmdir /s /q .gradle

REM Check if gradlew.bat exists
if not exist gradlew.bat (
    echo ERROR: gradlew.bat not found!
    pause
    exit /b 1
)

REM Build debug APK
echo Starting Gradle build...
gradlew.bat assembleDebug --stacktrace --info

REM Check if build was successful
if exist app\build\outputs\apk\debug\app-debug.apk (
    echo.
    echo ============================================
    echo  BUILD SUCCESSFUL!
    echo ============================================
    echo APK Location: app\build\outputs\apk\debug\app-debug.apk
    echo APK Size: 
    dir app\build\outputs\apk\debug\app-debug.apk
    echo.
    echo Ready for installation!
    echo ============================================
) else (
    echo.
    echo ============================================
    echo  BUILD FAILED!
    echo ============================================
    echo Check the error messages above.
    echo ============================================
)

pause
