#pragma once
//
// NutriculaLicenseCheck.h - the ONLY interface MQL ever sees. Two getters
// exposing the state machine's two variables (spec section 1), plus a
// "kick" function the EA calls periodically (e.g. from OnTimer/OnTick) to
// let the background logic actually run and progress.
//
// All exports are __cdecl with clean, undecorated names on both 32-bit and
// 64-bit builds - matching the existing project convention (see the
// Machine ID DLL's .def-file approach for 32-bit stdcall aliasing; this DLL
// avoids that entire problem by using __cdecl throughout instead).
//

#ifdef NUTRICULA_LICENSE_CHECK_EXPORTS
#define NUTRICULA_LC_API extern "C" __declspec(dllexport)
#else
#define NUTRICULA_LC_API extern "C" __declspec(dllimport)
#endif

// Returns the current INTERNAL_LICENSE_TIER: always exactly 1, 2, or -10.
NUTRICULA_LC_API int __cdecl Nutricula_GetLicenseTier();

// Returns the current INTERNAL_LICENSE_TIER_PENDING: -1, -2, -3, 1, 2, or -10.
NUTRICULA_LC_API int __cdecl Nutricula_GetLicensePending();

// Call periodically (every OnTick/OnTimer is fine - internally this is a
// cheap check unless real work is actually due). Ensures the local file is
// (re)checked and, if genuinely due, a background refresh is initiated or
// progressed. Never blocks the calling thread for the full 54-55 minute
// cycle - the actual wait/attempt loop runs on this DLL's own background
// worker thread; this call only needs to be cheap and frequent.
NUTRICULA_LC_API void __cdecl Nutricula_Poll();

// Optional one-time setup: pass the directory this DLL itself lives in (so
// it can find the neighboring Machine ID DLL and the server public key
// file). If never called, the DLL's own directory (derived from its module
// handle) is used automatically - this export exists only for a host that
// wants to override that.
NUTRICULA_LC_API int __cdecl Nutricula_Initialize(const wchar_t* dllDirectory);
