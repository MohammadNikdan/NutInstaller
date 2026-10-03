@echo off
REM ============================================================================
REM Builds NutriculaLicenseBroker64.exe using Dev-C++'s MinGW/g++.
REM
REM !!! BEFORE RUNNING: CoordinatorIdentityPrivate.h AND TransportKeyPrivate.h
REM     must be temporarily copied into ..\Coordinator\ and ..\LicenseCheck\
REM     (respectively) from your secure 01_DO_NOT_UPLOAD_TO_GITHUB folder.
REM     Remove them again immediately after this build completes. !!!
REM
REM !!! Set GPP64 to a g++.exe that itself produces 64-bit output - see
REM     build_LicenseCheck_x86.bat's comment for why -m32 is not used. !!!
REM ============================================================================

setlocal
REM GPPBIN is the plain, UNQUOTED bin folder - kept separate from GPP64/
REM WINDRES (which need their own quotes for use as commands) so it can
REM also be prepended to PATH further down without embedding stray quote
REM characters into PATH itself (a quoted PATH segment is not a valid
REM directory entry and would silently break PATH lookups).
set GPPBIN=C:\mingw64\bin
set GPP64="%GPPBIN%\g++.exe"
set WINDRES="%GPPBIN%\windres.exe"

if not exist %GPP64% (
    echo ERROR: g++.exe not found at %GPP64%
    echo Edit this script and set GPPBIN to your actual 64-bit WinLibs compiler folder.
    exit /b 1
)

REM --- windres.exe (resource compiler, embeds the Nutricula icon below) is
REM     expected right next to g++.exe in the same Dev-C++/TDM-GCC bin
REM     folder, which is the normal layout for every MinGW/TDM-GCC
REM     distribution - no separate path to configure.
if not exist %WINDRES% (
    echo ERROR: windres.exe not found at %WINDRES%
    echo It should sit next to g++.exe in the same Dev-C++/TDM-GCC bin folder.
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

REM --- Compile the Nutricula application icon (see
REM     ..\Coordinator\NutriculaCoordinatorIcon.rc) into a linkable object,
REM     so NutriculaLicenseBroker64.exe shows the Nutricula icon in Windows
REM     Explorer AND in Task Manager's Details tab - previously this exe had
REM     no icon resource at all. -F pe-x86-64 matches this script's 64-bit
REM     output; see build_Broker_x86.bat for the 32-bit equivalent.
REM
REM windres itself needs to run a C preprocessor over the .rc file first.
REM Left to its own default, windres builds that preprocessor's full path
REM (something like "...\TDM-GCC-64\bin\gcc.exe") WITHOUT quoting it, and
REM a path containing "Program Files (x86)" then breaks with
REM  'C:\Program' is not recognized as an internal or external command
REM (this was the actual cause behind the "opens and immediately closes"
REM symptom, and a separate/unrelated Windows "security warning" dialog
REM some people see for a freshly downloaded .bat/.exe is not related to
REM this). Fixed by TEMPORARILY adding this bin folder to PATH and telling
REM windres to invoke the preprocessor by its bare name only - a bare name
REM resolved via PATH never needs quoting, regardless of spaces/parentheses
REM in the folder it resolves to.
set PATH=%GPPBIN%;%PATH%
REM Built in %TEMP%, not in the repo/output folder - it's a throwaway
REM intermediate, already embedded into the final .exe by the g++ link
REM below, and deleted again right after that link succeeds.
set RES_OBJ=%TEMP%\NutriculaBuild_Broker_AppIcon_x64.o
%WINDRES% --preprocessor=gcc.exe --preprocessor-arg=-E --preprocessor-arg=-xc-header --preprocessor-arg=-DRC_INVOKED -F pe-x86-64 -O coff -o %RES_OBJ% ..\Coordinator\NutriculaCoordinatorIcon.rc
if %ERRORLEVEL% NEQ 0 (
    echo Failed to compile the Nutricula application icon resource.
    exit /b 1
)

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
REM
REM --- -mwindows (2026 bug fix): builds this exe as a GUI-subsystem binary
REM     instead of a console one, so Windows NEVER allocates/shows a console
REM     window for it - not on double-click, not from the DLL's own
REM     CreateProcessW (which already passed CREATE_NO_WINDOW), and NOT from
REM     the per-user Scheduled Task watchdog (InstallerService's schtasks.exe
REM     "/TR" action launches the exe directly, and Task Scheduler shows a
REM     console window of its own for a console-subsystem exe in an
REM     interactive session regardless of how it's invoked - CREATE_NO_WINDOW
REM     only has an effect if the LAUNCHING process requests it, which
REM     schtasks.exe does not). Safe: the Broker's few printf() calls
REM     (startup banner, singleton-exit message, missing-pubkey warning) are
REM     purely informational, read no input, and simply become silent no-ops
REM     with no console attached - nothing else in this binary needs a
REM     console. (The separate build_Broker_x64_DIAG.bat build intentionally
REM     does NOT add this flag, so its [PipeAuth] diagnostic output stays
REM     visible when run manually for troubleshooting.)
%GPP64% -D_WIN32_WINNT=0x0601 -std=c++17 -O2 -s -mwindows -static -static-libgcc -static-libstdc++ ^
    -I ..\Coordinator -I ..\LicenseCheck ^
    ..\Coordinator\NutriculaLicenseBroker.cpp ^
    ..\Coordinator\CoordinatorCore.cpp ^
    ..\Coordinator\ManifestVerify.cpp ^
    ..\LicenseCheck\LicenseProtocol.cpp ^
    ..\LicenseCheck\ServerSignatureVerify.cpp ^
    ..\LicenseCheck\Transport.cpp ^
    ..\LicenseCheck\MachineIdBridge.cpp ^
    %RES_OBJ% ^
    -o %OUT_DIR%\NutriculaLicenseBroker64.exe ^
    -lbcrypt -lcrypt32 -lwinhttp -ladvapi32

if %ERRORLEVEL% NEQ 0 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCEEDED: %OUT_DIR%\NutriculaLicenseBroker64.exe
del /f /q "%RES_OBJ%" >nul 2>&1
echo REMINDER: delete ..\Coordinator\CoordinatorIdentityPrivate.h AND ..\LicenseCheck\TransportKeyPrivate.h now.
endlocal
