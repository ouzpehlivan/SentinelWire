@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM SentinelWire™ Profile Builder v1.1
REM Installs Wireshark profile templates and replaces placeholders with environment-specific values.

title SentinelWire Profile Builder v1.1

echo ============================================================
echo   SentinelWire^™ Wireshark Profile Builder v1.1
echo   One-command install + personalization for all profiles
echo ============================================================
echo.

REM Validate PowerShell availability
where powershell >nul 2>&1
if errorlevel 1 (
  echo [ERROR] PowerShell not found. This installer requires Windows PowerShell.
  pause
  exit /b 1
)

REM Determine script directory and template source
set "SCRIPT_DIR=%~dp0"
set "SRC_PROFILES=%SCRIPT_DIR%profiles"

if not exist "%SRC_PROFILES%\" (
  echo [ERROR] Template profiles folder not found:
  echo         "%SRC_PROFILES%"
  echo Make sure you extracted the ZIP and kept the 'profiles' folder next to this BAT.
  pause
  exit /b 1
)

REM Destination: Wireshark profiles directory
set "DST_ROOT=%APPDATA%\Wireshark\profiles"
if not exist "%DST_ROOT%\" (
  echo [INFO] Creating Wireshark profiles folder:
  echo        "%DST_ROOT%"
  mkdir "%DST_ROOT%" >nul 2>&1
)

echo Step 1/3: Collect environment values
echo --------------------------------
set /p "USER_IP=Your workstation IP (e.g., 192.168.1.25): "
set /p "ROUTER_IP=Router/Default Gateway IP (e.g., 192.168.1.1): "
set /p "USER_MAC=Your workstation MAC (e.g., AA:BB:CC:DD:EE:FF): "
set /p "ROUTER_MAC=Router MAC (e.g., 11:22:33:44:55:66): "
echo.

REM Basic input sanity checks (lightweight)
if "%USER_IP%"==""  goto :badinput
if "%ROUTER_IP%"=="" goto :badinput
if "%USER_MAC%"=="" goto :badinput
if "%ROUTER_MAC%"=="" goto :badinput

echo Step 2/3: Install profile templates
echo -----------------------------------
for /d %%P in ("%SRC_PROFILES%\*") do (
  set "PNAME=%%~nP"
  echo [INFO] Installing profile: !PNAME!
  if exist "%DST_ROOT%\!PNAME!\" (
    echo        - Existing found, overwriting files
  )
  xcopy "%%P" "%DST_ROOT%\!PNAME!\" /E /I /Y >nul
)

echo.
echo Step 3/3: Personalize placeholders
echo ----------------------------------
REM Replace placeholders across installed profile files
REM Placeholders:
REM   {{USER_IP}}, {{ROUTER_IP}}, {{USER_MAC}}, {{ROUTER_MAC}}

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$dst='%DST_ROOT%';" ^
  "$repl=@{" ^
  "'{{USER_IP}}'='%USER_IP%';" ^
  "'{{ROUTER_IP}}'='%ROUTER_IP%';" ^
  "'{{USER_MAC}}'='%USER_MAC%';" ^
  "'{{ROUTER_MAC}}'='%ROUTER_MAC%'};" ^
  "Get-ChildItem -Path $dst -Recurse -File | ForEach-Object {" ^
  "  $p=$_.FullName;" ^
  "  try {" ^
  "    $c=Get-Content -LiteralPath $p -Raw -ErrorAction Stop;" ^
  "    foreach($k in $repl.Keys){ $c=$c.Replace($k,$repl[$k]) }" ^
  "    Set-Content -LiteralPath $p -Value $c -Encoding UTF8 -ErrorAction Stop" ^
  "  } catch { }" ^
  "};"

echo.
echo ============================================================
echo  Done. Profiles installed to:
echo    %DST_ROOT%
echo.
echo  In Wireshark:
echo    Edit ^> Configuration Profiles ^> select a SentinelWire profile
echo ============================================================
echo.
pause
exit /b 0

:badinput
echo [ERROR] Missing input value(s). Please re-run and provide all fields.
pause
exit /b 1
