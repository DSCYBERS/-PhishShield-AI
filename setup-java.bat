@echo off
echo Configuring Java Environment for PhishShield AI
echo.

REM Check common Java installation paths
set JAVA_PATHS=C:\Program Files\Eclipse Adoptium\jdk-11.0.20.8-hotspot\bin;C:\Program Files\Eclipse Adoptium\jdk-17.0.8.101-hotspot\bin;C:\Program Files\Java\jdk-11.0.20\bin;C:\Program Files\Java\jdk-17.0.8\bin

echo Searching for Java installation...
for %%i in (%JAVA_PATHS:;= %) do (
    if exist "%%i\java.exe" (
        echo Found Java at: %%i
        set JAVA_HOME=%%~pi
        set PATH=%%i;%PATH%
        goto :found
    )
)

echo Java not found in common locations.
echo Please install Java JDK from: https://adoptium.net/temurin/releases/
echo Choose OpenJDK 11 LTS, Windows x64, JDK, .msi installer
pause
exit /b 1

:found
echo.
echo ============================================
echo Java Configuration Complete!
echo ============================================
echo JAVA_HOME: %JAVA_HOME%
echo.
echo Testing Java...
java -version
echo.
echo ============================================
echo Ready for Android Studio installation!
echo ============================================
pause
