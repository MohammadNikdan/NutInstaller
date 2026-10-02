@echo off
REM ============================================================================
REM Builds MachineId64.dll using the 64-bit WinLibs MinGW-w64 g++.
REM
REM !!! Compiler: GPP64 points at the 64-bit WinLibs x86_64 / POSIX-threads
REM     toolchain at C:\mingw64. No -m32 is used here. !!!
REM ============================================================================

setlocal
set GPP64="C:\mingw64\bin\g++.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPP64 to your actual 64-bit WinLibs compiler path.
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
