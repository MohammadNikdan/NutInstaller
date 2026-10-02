@echo off
REM ============================================================================
REM Builds Keys\KeyBaker.exe - the tool every other build_*.bat runs first
REM to turn genuine PEM/hex files in Keys\ into #include-able headers.
REM Build this ONCE (rebuild only if KeyBaker.cpp itself changes).
REM ============================================================================

setlocal
set GPP64="C:\mingw64\bin\g++.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPP64 to your actual 64-bit WinLibs compiler path.
    exit /b 1
)

%GPP64% -D_WIN32_WINNT=0x0601 -std=c++17 -O2 -static -static-libgcc -static-libstdc++ ^
    ..\Coordinator\KeyBaker.cpp ^
    -lcrypt32 ^
    -o ..\Keys\KeyBaker.exe

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: ..\Keys\KeyBaker.exe
echo Now every other build_*.bat will automatically use it.
endlocal
