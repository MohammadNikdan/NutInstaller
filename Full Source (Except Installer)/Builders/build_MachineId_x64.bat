@echo off
REM ============================================================================
REM Builds MachineId64.dll using Dev-C++'s MinGW/g++.
REM
REM !!! Compiler: using TDM-GCC-64 with the flag - see
REM     build_LicenseCheck_x86.bat's comment for the full explanation and
REM     what to do if this fails with an "ldscripts/i386pe.x" error. !!!
REM ============================================================================

setlocal
set GPP64="C:\Program Files (x86)\Embarcadero\Dev-Cpp\TDM-GCC-64\bin\g++.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPP64 to your actual 64-bit Dev-C++ compiler path.
    exit /b 1
)

REM --- Bake keys from Keys\*.pem/txt first - MachineId.dll needs
REM     TransportKey_Generated.h too. ---
if not exist "..\Keys\KeyBaker.exe" (
    echo ERROR: ..\Keys\KeyBaker.exe not found - build it once with build_KeyBaker.bat.
    exit /b 1
)
..\Keys\KeyBaker.exe "%CD%\..\Keys"
if %ERRORLEVEL% NEQ 0 (
    echo KeyBaker failed - see errors above. Build stopped.
    exit /b 1
)

set OUT_DIR=Builds
if not exist %OUT_DIR% mkdir %OUT_DIR%

%GPP64% -D_WIN32_WINNT=0x0601 -std=c++17 -O2 -shared -static-libgcc -static-libstdc++ ^
    -I ..\MachineID ^
    ..\MachineID\NutriculaMachineId.cpp ^
    -o %OUT_DIR%\MachineId64.dll ^
    -lwbemuuid -lole32 -loleaut32 -ladvapi32 -lbcrypt -lcrypt32 -lwinhttp

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: %OUT_DIR%\MachineId64.dll
endlocal
