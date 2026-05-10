@echo off
REM Wrapper for patch_zero_exe.py.
REM Part of the Trails From Zero Toolkit. Author: Edrahor.

setlocal

REM Set EXE to the absolute path of your zero.exe before running.
REM Example: set EXE="C:\Program Files (x86)\Steam\steamapps\common\The Legend of Heroes Trails from Zero\zero.exe"
set EXE="PATH\TO\zero.exe"
set SCRIPT="%~dp0patch_zero_exe.py"

if %EXE%=="PATH\TO\zero.exe" (
    echo ERROR: edit apply_patch.bat and set EXE to your zero.exe path.
    exit /b 1
)

if "%~1"=="dry" (
    echo === DRY RUN ALL PATCHES ===
    python %SCRIPT% --dry-run %EXE%
    goto :eof
)

if "%~1"=="revert" (
    echo === REVERT ALL PATCHES ===
    python %SCRIPT% --revert %EXE%
    goto :eof
)

if /i "%~1"=="P1" (
    echo === APPLY ONLY P1 ===
    python %SCRIPT% --only P1 %EXE%
    goto :eof
)

if /i "%~1"=="P2" (
    echo === APPLY ONLY P2 ===
    python %SCRIPT% --only P2 %EXE%
    goto :eof
)

if /i "%~1"=="P3" (
    echo === APPLY ONLY P3 ===
    python %SCRIPT% --only P3 %EXE%
    goto :eof
)

if /i "%~1"=="P4" (
    echo === APPLY ONLY P4 ===
    python %SCRIPT% --only P4 %EXE%
    goto :eof
)

if /i "%~1"=="P5" (
    echo === APPLY ONLY P5 ===
    python %SCRIPT% --only P5 %EXE%
    goto :eof
)

if /i "%~1"=="revert-P1" (
    echo === REVERT ONLY P1 ===
    python %SCRIPT% --revert --only P1 %EXE%
    goto :eof
)

if /i "%~1"=="revert-P2" (
    echo === REVERT ONLY P2 ===
    python %SCRIPT% --revert --only P2 %EXE%
    goto :eof
)

if /i "%~1"=="revert-P3" (
    echo === REVERT ONLY P3 ===
    python %SCRIPT% --revert --only P3 %EXE%
    goto :eof
)

if /i "%~1"=="revert-P4" (
    echo === REVERT ONLY P4 ===
    python %SCRIPT% --revert --only P4 %EXE%
    goto :eof
)

if /i "%~1"=="revert-P5" (
    echo === REVERT ONLY P5 ===
    python %SCRIPT% --revert --only P5 %EXE%
    goto :eof
)

echo === APPLY ALL PATCHES ===
python %SCRIPT% %EXE%
echo.
echo Usage:
echo   apply_patch.bat              -- apply all patches (default)
echo   apply_patch.bat dry          -- dry run, no writes
echo   apply_patch.bat revert       -- revert all patches
echo   apply_patch.bat P1           -- apply only P1 (encoding detector fix)
echo   apply_patch.bat P2           -- apply only P2 (item description fix)
echo   apply_patch.bat P3           -- apply only P3 (quest preview truncate fix)
echo   apply_patch.bat P4           -- apply only P4 (multi-line formatter, simple)
echo   apply_patch.bat P5           -- apply only P5 (rich multi-line formatter)
echo   apply_patch.bat revert-P1    -- revert only P1
echo   apply_patch.bat revert-P2    -- revert only P2
echo   apply_patch.bat revert-P3    -- revert only P3
echo   apply_patch.bat revert-P4    -- revert only P4
echo   apply_patch.bat revert-P5    -- revert only P5
