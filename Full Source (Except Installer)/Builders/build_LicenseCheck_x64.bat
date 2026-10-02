@echo off
REM ============================================================================
REM Builds NutriculaLicenseCheck64.dll using Dev-C++'s MinGW/g++.
REM
REM !!! IMPORTANT: set GPP64 to the g++.exe that itself produces 64-bit
REM     output. Find it via Dev-C++ > Tools > Compiler Options > (select
REM     your 64-bit profile) > "..." next to the compiler path. Do NOT
REM     rely on a -m32 flag - tested and confirmed unreliable: it fails
REM     outright on MinGW-w64 installs that were built 64-bit-only
REM     (no multilib support), which is common. Pointing directly at a
REM     genuinely 64-bit-targeting g++.exe always works instead.
REM ============================================================================

setlocal
set GPP64="C:\mingw64\bin\g++.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPP64 to your actual 64-bit WinLibs compiler path.
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

set SRC_DIR=..\LicenseCheck
set OUT_DIR=Builds
if not exist %OUT_DIR% mkdir %OUT_DIR%

REM --- -s (strip) removes the symbol table from the output binary. WITHOUT
REM     it, the names of INTERNAL (non-exported) functions stay embedded and
REM     readable in the shipped file - verified directly: `nm`/`strings` on an
REM     unstripped build happily lists them (CoordinatorCore::EvaluateLocalFile,
REM     EstimatedNow, ...), handing a reverse engineer a free map of the code.
REM     Stripping removes those names while leaving the DLL export table, the
REM     .rsrc icon and the .pdata/.xdata exception-unwind tables fully intact
REM     (all three verified), so runtime behavior is completely unchanged.
REM     NOTE: this changes the binary's SHA-256, so the manifest MUST be
REM     regenerated with NutriculaSignTool after rebuilding.
%GPP64% -D_WIN32_WINNT=0x0601 -std=c++17 -O2 -s -shared -static -static-libgcc -static-libstdc++ ^
    -I %SRC_DIR% -I ..\Coordinator ^
    %SRC_DIR%\NutriculaLicenseCheckThin.cpp ^
    %SRC_DIR%\ServerSignatureVerify.cpp ^
    -o %OUT_DIR%\NutriculaLicenseCheck64.dll ^
    -lbcrypt -lcrypt32 -ladvapi32

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: %OUT_DIR%\NutriculaLicenseCheck64.dll
endlocal
