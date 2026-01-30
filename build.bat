@echo off
REM VAJRA Shakti Kavach - Windows Build Script
REM Builds Windows EXE installer

setlocal enabledelayedexpansion

echo.
echo VAJRA Shakti Kavach - Windows Builder
echo =====================================
echo.

set PLATFORM=%1
if "%PLATFORM%"=="" set PLATFORM=all

REM Check for Node.js
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Node.js not found. Please install Node.js first.
    exit /b 1
)

REM Check for Git
where git >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Git not found. Please install Git first.
    exit /b 1
)

echo Checking dependencies...
npm list electron-builder >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Installing dependencies...
    call npm install
)

mkdir dist 2>nul

if "%PLATFORM%"=="windows" goto build_windows
if "%PLATFORM%"=="win" goto build_windows
if "%PLATFORM%"=="all" goto build_windows

:help
echo.
echo Usage: build.bat [windows^|android^|ios^|all]
echo.
echo Examples:
echo   build.bat windows    - Build Windows EXE
echo   build.bat all        - Build all desktop apps
echo.
goto end

:build_windows
echo.
echo Building Windows EXE...
call npm run build-win
if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b 1
)
echo.
echo Build complete! Check dist\ folder for executables.
goto end

:end
echo.
pause
