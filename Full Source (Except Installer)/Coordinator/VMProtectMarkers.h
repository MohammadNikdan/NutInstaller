#pragma once
//
// VMProtectMarkers.h - thin, no-op-by-default wrapper around VMProtect's
// own SDK Begin/End virtualization markers.
//
// WHY A WRAPPER INSTEAD OF CALLING THE SDK DIRECTLY: EcdsaHelpers.h and
// NamedPipeIpc.h (which this header is included from) are shared, header-
// only code, compiled into MULTIPLE binaries - the thin License Check
// DLL, the Coordinator/Broker, and NutriculaSignTool/ManifestVerify. Only
// the thin DLL is meant to go through VMProtect. Calling the SDK's real
// macros directly in a shared header would force every one of those other
// binaries to also link the VMProtect SDK library for no reason, and
// would break their builds the moment the SDK files aren't present.
//
// Instead, NUT_VMP_BEGIN/_ULTRA/_END below compile to PLAIN NO-OPS (empty
// statements - zero size, zero behavior change) everywhere, UNLESS the
// specific translation unit's build defines NUTRICULA_VMPROTECT_BUILD.
// Only build_LicenseCheck_x64.bat / build_LicenseCheck_x86.bat define
// that macro (see the commented-out block near the bottom of each), so
// only the thin DLL build is ever affected. The Coordinator/Broker,
// NutriculaSignTool, and every other consumer of these shared headers
// keep compiling exactly as before, with no new dependency at all.
//
// ----------------------------------------------------------------------
// SETUP REQUIRED BEFORE NUTRICULA_VMPROTECT_BUILD CAN BE DEFINED:
//
// This file does NOT and CANNOT contain VMProtect's actual SDK - that is
// VMProtect's own copyrighted, licensed-to-your-installation code, not
// something that can be generated or substituted. You must copy it
// yourself, once, from your own installed copy of VMProtect:
//
//   1. Find VMProtect's SDK folder - typically:
//        C:\Program Files\VMProtect Ultimate\SDK\C\
//      It contains VMProtectSDK.h and a set of compiled libraries for
//      different compilers/architectures (VMProtectSDK32.lib,
//      VMProtectSDK64.lib, and similar).
//
//   2. Copy VMProtectSDK.h into this project's LicenseCheck\ folder
//      (next to NutriculaLicenseCheckThin.cpp).
//
//   3. The .lib files VMProtect ships are in MSVC's COFF/.lib format,
//      which g++/MinGW's linker (ld) cannot read directly. You need an
//      import library MinGW can link against. VMProtect's SDK folder
//      usually also ships a .def file (e.g. VMProtectSDK64.def) for
//      exactly this situation - if it's there, generate a MinGW-
//      compatible import library yourself with dlltool (ships with
//      MinGW, no extra download):
//
//        dlltool -d VMProtectSDK64.def -l libVMProtectSDK64.a
//        dlltool -d VMProtectSDK32.def -l libVMProtectSDK32.a
//
//      Put the resulting libVMProtectSDK64.a / libVMProtectSDK32.a next
//      to VMProtectSDK.h in LicenseCheck\. (If no .def ships with your
//      VMProtect version, open a cmd prompt in the SDK\C folder and run
//      `dumpbin /exports VMProtectSDK64.lib` to list the exported
//      function names, then write a minimal .def by hand listing just
//      those names under an EXPORTS line - this is a one-time, 5-minute
//      task, and the function set is small and stable:
//      VMProtectBeginVirtualization, VMProtectBeginMutation,
//      VMProtectBeginUltra, VMProtectEnd, and a handful of license-
//      checking functions this project does not use.)
//
//   4. Only then uncomment the NUTRICULA_VMPROTECT_BUILD block near the
//      bottom of build_LicenseCheck_x64.bat and build_LicenseCheck_x86.bat.
//      Until you do that, these macros stay no-ops and both scripts build
//      exactly as they do today - nothing here changes current behavior.
// ----------------------------------------------------------------------

#ifdef NUTRICULA_VMPROTECT_BUILD
    #if defined(__GNUC__) && !defined(_MSC_VER)
        // VMProtectSDK.h picks its import library by checking MSVC's
        // compiler-builtin _M_IX86/_M_X64/_M_ARM64 macros. Under real MSVC
        // those are defined from the very first line of the file, with no
        // header needed, so include order never matters there. Under
        // MinGW/g++ (what every .bat in this project actually uses),
        // those macros only come to exist once <windows.h> (or one of its
        // MinGW-internal compatibility headers) has been included -
        // that's where MinGW defines them, purely for MSVC-source
        // compatibility like this. A few translation units in this project
        // include this header before their own <windows.h> include (plain
        // header-ordering, nothing load-bearing), which left none of those
        // three macros defined yet and tripped VMProtectSDK.h's own
        // #error "Unsupported target architecture" - even though the
        // build genuinely does target x86/x64 correctly. Including
        // <windows.h> right here guarantees the macros exist in time, with
        // zero effect on what the final binary does: windows.h is always
        // included again later in each .cpp regardless, and its own
        // include guard makes that repeat a complete no-op.
        #include <windows.h>
    #endif
    #include "VMProtectSDK.h"
    #define NUT_VMP_BEGIN(name)          VMProtectBeginVirtualization(name)
    #define NUT_VMP_BEGIN_ULTRA(name)    VMProtectBeginUltra(name)
    #define NUT_VMP_BEGIN_MUTATION(name) VMProtectBeginMutation(name)
    #define NUT_VMP_END()                VMProtectEnd()
#else
    #define NUT_VMP_BEGIN(name)          do { } while (0)
    #define NUT_VMP_BEGIN_ULTRA(name)    do { } while (0)
    #define NUT_VMP_BEGIN_MUTATION(name) do { } while (0)
    #define NUT_VMP_END()                do { } while (0)
#endif
