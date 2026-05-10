@echo off
REM Build font.itf from a TTF + the replacement table in config_font.ini.
REM Run from this directory.
REM Wrapper for glyph.py (Ivdos / adapted by Edrahor) for the Trails From Zero Toolkit.

setlocal
cd /d "%~dp0"

echo ============================================================
echo Building font.itf from config_font.ini
echo ============================================================

if not exist config_font.ini (
    echo ERROR: config_font.ini not found.
    pause
    exit /b 1
)

REM Backup current font.itf if not yet backed up
if exist font.itf (
    if not exist font.itf.bak (
        copy /Y font.itf font.itf.bak >nul
        echo Backup saved: font.itf.bak
    )
)

python -X utf8 glyph.py
if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo Done. font.itf ready.
echo ============================================================
pause
