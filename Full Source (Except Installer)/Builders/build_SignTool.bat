@echo off
REM ============================================================================
REM Builds NutriculaSignTool.exe using Dev-C++'s MinGW/g++.
REM
REM !!! BEFORE RUNNING: VendorSigningKey_Private.pem (and _Public.pem) must
REM     have real values in Keys\ - see Keys\README.txt if they're empty. !!!
REM ============================================================================

setlocal
set GPP64="C:\Program Files (x86)\Embarcadero\Dev-Cpp\TDM-GCC-64\bin\g++.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPP64 to your actual 64-bit Dev-C++ compiler path.
    exit /b 1
)

REM --- Bake keys from Keys\*.pem first - NutriculaSignTool needs the
REM     Vendor key's Generated.h files. ---
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

%GPP64% -std=c++17 -O2 -static-libgcc -static-libstdc++ ^
    ..\SignTool\NutriculaSignTool.cpp ^
    ..\Coordinator\ManifestVerify.cpp ^
    -o %OUT_DIR%\NutriculaSignTool.exe ^
    -lbcrypt -lcrypt32

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: %OUT_DIR%\NutriculaSignTool.exe
endlocal
