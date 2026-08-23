@echo off
REM ============================================================================
REM Builds NutriculaLicenseBroker32.exe using Dev-C++'s MinGW/g++.
REM
REM !!! BEFORE RUNNING: CoordinatorIdentityPrivate.h AND TransportKeyPrivate.h
REM     must be temporarily copied into ..\Coordinator\ and ..\LicenseCheck\
REM     (respectively) from your secure 01_DO_NOT_UPLOAD_TO_GITHUB folder.
REM     Remove them again immediately after this build completes. !!!
REM
REM !!! Set GPP32 to a g++.exe that itself produces 32-bit output - see
REM     build_LicenseCheck_x86.bat's comment for why -m32 is not used. !!!
REM ============================================================================

setlocal
set GPP32="C:\Program Files (x86)\Embarcadero\Dev-Cpp\TDM-GCC-64\bin\g++.exe"

if not exist %GPP32% (
    echo ERROR: g++.exe not found at %GPP32%
    echo Edit this script and set GPP32 to your actual 32-bit Dev-C++ compiler path.
    exit /b 1
)

if not exist "..\Coordinator\CoordinatorIdentityPrivate.h" (
    echo ERROR: CoordinatorIdentityPrivate.h is missing from ..\Coordinator\
    echo Copy it there temporarily from 01_DO_NOT_UPLOAD_TO_GITHUB before building.
    exit /b 1
)
if not exist "..\LicenseCheck\TransportKeyPrivate.h" (
    echo ERROR: TransportKeyPrivate.h is missing from ..\LicenseCheck\
    echo Copy it there temporarily from 01_DO_NOT_UPLOAD_TO_GITHUB before building.
    exit /b 1
)


REM --- Bake keys from Keys\*.pem into the source tree's *_Generated.h
REM     files - always run this before compiling, since it is what turns
REM     genuine openssl PEM output into something #include-able. If a
REM     required key file is empty or missing, KeyBaker stops here with a
REM     clear error, before g++ is ever invoked.
if not exist "..\Keys\KeyBaker.exe" (
    echo ERROR: ..\Keys\KeyBaker.exe not found - build it once from
    echo Coordinator\KeyBaker.cpp with any of the g++ compilers above.
    exit /b 1
)
..\Keys\KeyBaker.exe "%CD%\..\Keys"
if %ERRORLEVEL% NEQ 0 (
    echo KeyBaker failed - see errors above. Build stopped.
    exit /b 1
)

set OUT_DIR=Builds
if not exist %OUT_DIR% mkdir %OUT_DIR%

%GPP32% -m32 -D_WIN32_WINNT=0x0601 -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    -I ..\Coordinator -I ..\LicenseCheck ^
    ..\Coordinator\NutriculaLicenseBroker.cpp ^
    ..\Coordinator\CoordinatorCore.cpp ^
    ..\Coordinator\ManifestVerify.cpp ^
    ..\LicenseCheck\LicenseProtocol.cpp ^
    ..\LicenseCheck\ServerSignatureVerify.cpp ^
    ..\LicenseCheck\Transport.cpp ^
    ..\LicenseCheck\MachineIdBridge.cpp ^
    -o %OUT_DIR%\NutriculaLicenseBroker32.exe ^
    -lbcrypt -lcrypt32 -lwinhttp -ladvapi32

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: %OUT_DIR%\NutriculaLicenseBroker32.exe
echo REMINDER: delete ..\Coordinator\CoordinatorIdentityPrivate.h AND ..\LicenseCheck\TransportKeyPrivate.h now.
endlocalREM !!! Compiler: using TDM-GCC-64 with the -m32 flag to cross-compile to
REM     32-bit. The REAL TDM-GCC project (unlike a plain single-arch
REM     mingw-w64 build) is usually multilib-capable, meaning its 64-bit
REM     g++.exe can ALSO produce 32-bit output when given -m32 - this is
REM     why the same TDM-GCC-64 path is reused here.
REM
REM     IF THIS SCRIPT FAILS with an error like:
REM       "cannot open linker script file ldscripts/i386pe.x"
REM     that means this specific TDM-GCC-64 install is NOT multilib-
REM     capable, and -m32 cannot work with it at all. In that case, you
REM     need a genuinely separate 32-bit-targeting compiler installed
REM     (e.g. Dev-C++'s older/32-bit MinGW package, if available), and
REM     should point GPP32 at THAT g++.exe instead, removing the -m32
REM     flag below (a 32-bit-only compiler already only ever produces
REM     32-bit output, so -m32 becomes unnecessary/redundant with one).
REM

