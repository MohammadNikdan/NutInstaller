@echo off
REM ============================================================================
REM Generate_All_Keys.bat
REM
REM Double-click this file. It builds all 7 key files THIS project needs,
REM right next to itself, using the openssl.exe already installed on YOUR
REM computer. Nothing is sent anywhere - everything stays on this machine.
REM
REM !!! WARNING - READ BEFORE RUNNING !!!
REM Running this OVERWRITES any key files already sitting next to it.
REM After it finishes:
REM   1. Re-run KeyBaker.exe (it reads these same 6 .pem files + TransportKey.txt
REM      and rebuilds the *_Generated.h headers from them).
REM   2. Rebuild EVERY native binary (LicenseCheck, MachineId, Coordinator/
REM      Broker - both x86 and x64) and the Installer, since they all now
REM      carry stale keys until rebuilt.
REM   3. Re-run NutriculaSignTool.exe (new manifest.txt) and
REM      NutriculaSignInstaller.exe (re-sign the new Installer.exe).
REM   4. Upload the NEW ServerLicenseSigningKey_Private.pem and the NEW
REM      TransportKey.txt to your live server, to the exact paths your real
REM      license_config.php points at - overwriting the old ones there.
REM   5. Only do step 4 once the new build from steps 1-3 is fully ready -
REM      the moment you do step 4, every OLD build (including whatever is
REM      on your test machine right now) stops working.
REM
REM Needs openssl.exe to be installed and reachable. If "openssl" is not
REM already on your PATH, edit the line below and put its full path instead
REM (e.g. "C:\Program Files\Git\usr\bin\openssl.exe" - it ships inside
REM Git for Windows, so if you have Git installed you already have it there).
REM ============================================================================

setlocal
set OPENSSL=openssl

where %OPENSSL% >nul 2>nul
if errorlevel 1 (
    echo ERROR: "%OPENSSL%" was not found on your PATH.
    echo Edit this .bat file and set OPENSSL to the full path of openssl.exe
    echo ^(for example: set OPENSSL="C:\Program Files\Git\usr\bin\openssl.exe"^)
    pause
    exit /b 1
)

cd /d "%~dp0"
echo Generating into: %cd%
echo.

echo [1/4] Vendor Signing Key (EC P-256, SEC1 private / SPKI public)
%OPENSSL% ecparam -name prime256v1 -genkey -noout -out VendorSigningKey_Private.pem
if errorlevel 1 goto :fail
%OPENSSL% ec -in VendorSigningKey_Private.pem -pubout -out VendorSigningKey_Public.pem 2>nul
if errorlevel 1 goto :fail
echo   -^> VendorSigningKey_Private.pem, VendorSigningKey_Public.pem
echo.

echo [2/4] Coordinator Identity Key (EC P-256, SEC1 private / SPKI public)
%OPENSSL% ecparam -name prime256v1 -genkey -noout -out CoordinatorIdentityKey_Private.pem
if errorlevel 1 goto :fail
%OPENSSL% ec -in CoordinatorIdentityKey_Private.pem -pubout -out CoordinatorIdentityKey_Public.pem 2>nul
if errorlevel 1 goto :fail
echo   -^> CoordinatorIdentityKey_Private.pem, CoordinatorIdentityKey_Public.pem
echo.

echo [3/4] Server License Signing Key (RSA 4096, PKCS1 private / SPKI public)
%OPENSSL% genrsa -out ServerLicenseSigningKey_Private.pem 4096 2>nul
if errorlevel 1 goto :fail
%OPENSSL% rsa -in ServerLicenseSigningKey_Private.pem -pubout -out ServerLicenseSigningKey_Public.pem 2>nul
if errorlevel 1 goto :fail
echo   -^> ServerLicenseSigningKey_Private.pem (upload to the SERVER only, never into a client build)
echo   -^> ServerLicenseSigningKey_Public.pem   (this is the one KeyBaker bakes into the client)
echo.

echo [4/4] Transport Key (32 random bytes, 64 lowercase hex characters)
%OPENSSL% rand -hex 32 > TransportKey.txt
if errorlevel 1 goto :fail
echo   -^> TransportKey.txt
echo.

echo Round-trip self-test (sign+verify each key, exactly like the real code does):
echo self-test> selftest.msg
%OPENSSL% dgst -sha256 -sign ServerLicenseSigningKey_Private.pem -out selftest.sig selftest.msg
%OPENSSL% dgst -sha256 -verify ServerLicenseSigningKey_Public.pem -signature selftest.sig selftest.msg
if errorlevel 1 goto :fail
%OPENSSL% dgst -sha256 -sign VendorSigningKey_Private.pem -out selftest.sig selftest.msg
%OPENSSL% dgst -sha256 -verify VendorSigningKey_Public.pem -signature selftest.sig selftest.msg
if errorlevel 1 goto :fail
%OPENSSL% dgst -sha256 -sign CoordinatorIdentityKey_Private.pem -out selftest.sig selftest.msg
%OPENSSL% dgst -sha256 -verify CoordinatorIdentityKey_Public.pem -signature selftest.sig selftest.msg
if errorlevel 1 goto :fail
del selftest.msg selftest.sig

echo.
echo ============================================================
echo  All 7 files created and verified successfully:
echo ============================================================
dir /b VendorSigningKey_Private.pem VendorSigningKey_Public.pem ^
    CoordinatorIdentityKey_Private.pem CoordinatorIdentityKey_Public.pem ^
    ServerLicenseSigningKey_Private.pem ServerLicenseSigningKey_Public.pem ^
    TransportKey.txt
echo.
echo Done. Now do the 5 steps listed in the warning comment at the top of
echo this file (re-run KeyBaker, rebuild everything, re-sign, then upload
echo the two server files only once the new build is ready).
echo.
pause
exit /b 0

:fail
echo.
echo BUILD FAILED - see the error above.
pause
exit /b 1
