#pragma once
//
// RuntimeMeasure.h - measures the artifacts that are GENUINELY RUNNING on
// this machine, instead of the private copies an installer left in a folder
// of its own.
//
// WHY THIS REPLACED THE OLD SCHEME (2026, project owner's decision)
// -----------------------------------------------------------------
// Until now the Coordinator hashed the ex4/ex5/DLL copies the Installer had
// placed next to itself in %LOCALAPPDATA%\Nutricula\LicenseService and
// compared those against the Vendor-signed manifest. That check could never
// catch the attack it existed for: someone patching the EA or a DLL does not
// touch the Coordinator's private copies at all - they leave those pristine
// and run their own patched file from wherever MetaTrader actually loads it.
// The copies matched, every check passed, and the patched code ran happily.
//
// So every measurement here is taken from the thing that is actually loaded
// or actually executing:
//   * the Broker's own running image          -> GetModuleFileNameW(nullptr)
//   * the MachineId DLL the Broker loaded     -> its own module handle
//   * the License Check DLL inside MetaTrader -> that process's real module
//                                                list, read from the OS
//   * the MachineId DLL inside MetaTrader     -> same, when it is loaded
//   * the EA that MetaTrader can run          -> the terminal's own
//                                                Experts/Indicators/Scripts
//
// NOTHING IS ASKED OF THE EA, AND NOTHING IS TRUSTED BY NAME
// ----------------------------------------------------------
// The obvious design would be for the EA to report MQLInfoString(
// MQL_PROGRAM_PATH) and for us to hash that. It is also worthless: an EA
// patched to remove the license check is equally capable of reporting the
// path of a pristine copy sitting next to it. Everything here is therefore
// derived from the operating system or from the file system, never from a
// value the EA (or the DLL inside its process) hands us:
//   - the terminal process identity comes from the pipe
//     (GetNamedPipeClientProcessId), which the client cannot forge;
//   - the loaded module paths come from that process's module list, which
//     the client cannot rewrite;
//   - our own modules are picked out of that list BY HASH, not by file
//     name, so copying the License Check DLL to some other name and
//     importing that instead changes nothing - the copy is byte-identical,
//     so it is still recognised;
//   - the terminal's data folder is derived from the resolved DLL's own
//     loaded path (<data>\MQL4|5\Libraries\<file>), so it follows the real
//     module rather than anybody's claim about where it is;
//   - the program is found by scanning that terminal's own Experts,
//     Indicators and Scripts trees (recursively), which are the only places
//     MetaTrader loads a compiled MQL program from.
//
// THE TWO TREE RULES, AND WHY BOTH ARE NEEDED
// -------------------------------------------
//   1. EVERY file in those trees that is recognisably Nutricula must hash to
//      the manifest's expected value. One that does not is tampering - it
//      makes no difference how many files there are, or whether a genuine
//      copy sits beside them.
//   2. At least one file matching that expectation must exist.
//
// Rule 1 alone could be dodged by scrubbing whatever makes a file
// "recognisable" out of the patched copy. Rule 2 is what makes that pointless
// in the common case: replace the genuine file and rule 2 fails, because the
// expected hash is then nowhere in the tree.
//
// What is left is keeping the genuine file AND adding a scrubbed patched
// copy. For that, recognition cannot rest on a marker an attacker is free to
// delete, so a file is recognisable by any of:
//   (a) an explicit build marker in the EA source - easy to scrub, kept only
//       as redundancy;
//   (b) the DEFAULT License Check DLL file names;
//   (c) the base name of every file in that terminal's own Libraries tree
//       that is byte-identical to our License Check DLL;
//   (d) the DLL's exported entry-point names (Vela_Boot_84, Pavo_Sync_85,
//       ...), which the compiled program carries for every imported function
//       it calls.
// (c) and (d) are the ones that matter, and neither can be scrubbed. A
// patched EA is worthless unless it can still reach the ~1020 real
// calculations, which live in that DLL - so it must import the library AND
// name the functions, and MQL resolves both by name at run time, never by
// ordinal. Renaming the DLL does not help either: whatever name the copy is
// given, the copy is byte-identical to ours, so (c) picks that name up.
//
// The same two lists do a second job on the module side. A module loaded in
// the terminal that carries our entry-point names but matches no expected
// hash is a MODIFIED build of one of our DLLs - renamed, so hash matching
// alone would have dismissed it as somebody else's library - and that fails
// the session whether or not a genuine DLL is loaded beside it.
//
// WHAT IS STILL OPEN (stated plainly, not papered over)
// -----------------------------------------------------
// A wrapper DLL that resolves our exports BY ORDINAL (GetProcAddress with a
// number instead of a name) carries none of the strings above, and a patched
// program importing only that wrapper is not recognised. Everything cheaper
// than that is covered: a wrapper that imports by name carries the names and
// is caught as a modified module.
//
// It is worth knowing what that costs an attacker - writing native code -
// which is the same tier of effort as attacking the License Check DLL or the
// Broker directly. That layer is defended elsewhere: by hashing the loaded
// DLL from a different process, and by the server's signature chain.
//
// HOW THIS COMBINES WITH THE TIER GATE
// ------------------------------------
// Patching the EA to ignore its own licence check does not buy anything, and
// that is worth spelling out because it is the attack people assume works
// against MQL bytecode. It fails here for a structural reason: the EA does
// not hold the logic. The ~1020 real calculations live in the License Check
// DLL behind EffectiveTier(), so what the EA does with a verdict is almost
// irrelevant - what matters is which verdict the DLL is willing to act on. A
// modified program in the tree makes this measurement fail, the Coordinator
// publishes TIER_FAILED (-2), and from that moment the DLL hands back decoy
// values no matter what the EA asks for. Removing the alert and the
// ExpertRemove() from a patched EA only means it keeps running on wrong
// numbers.
//

#include <windows.h>
#include <string>
#include <vector>

namespace RuntimeMeasure {

// The per-artifact expectations from the Vendor-signed manifest. Passed in
// whole rather than pre-selected by the caller, because WHICH expectation
// applies is something this code resolves (by hash and by the resolved DLL's
// own path), not something the caller can know in advance.
struct ManifestExpectations
{
    std::string ex4Sha256;
    std::string ex5Sha256;
    std::string dll32Sha256;
    std::string dll64Sha256;
    std::string machineid32Sha256;
    std::string machineid64Sha256;
};

// One MetaTrader process that genuinely talked to this Coordinator over the
// pipe. Everything in here was read from the OS, not reported by the client.
struct TerminalSession
{
    DWORD pid = 0;
    // Process creation time, from GetProcessTimes. Windows reuses PIDs, so a
    // session is identified by (pid, createdAt) - never by pid alone, or a
    // dead terminal's measurements could be attributed to an unrelated
    // process that later inherited its PID.
    unsigned long long createdAt100ns = 0;
    // Every loaded module in that process that a user could have put there -
    // that is, everything outside the Windows directory. Our own modules are
    // found in this list by HASH (see MeasureSession), which is why the list
    // is deliberately not filtered by file name.
    std::vector<std::wstring> candidateModules;
    // The subset whose base name is one of our shipped names. Used only to
    // produce a precise failure reason when nothing in the list matches the
    // manifest - "the DLL loaded under our name is not ours" is a far more
    // useful -2 detail than "nothing recognisable was found".
    std::vector<std::wstring> nameMatchedModules;
    unsigned long long noticedTickMs = 0; // GetTickCount64() of the last pipe contact
};

// Reads the above for the process on the other end of an already connected,
// already authenticated pipe. Returns false (with a human-readable reason in
// outDetail) when the client is not a MetaTrader process running Nutricula
// at all - a diagnostic tool connecting to the pipe, say - so that such a
// connection is simply not tracked rather than counted as a broken terminal.
//
// `expected` may be empty on the very first contact, before the worker has
// loaded the manifest; identification then falls back to the shipped file
// names for that round, and the next re-discovery uses hashes.
bool DiscoverSessionFromPipe(HANDLE pipe, const ManifestExpectations& expected,
    TerminalSession& out, std::string& outDetail);

// True while that exact process (same pid AND same creation time) is still
// running. A session whose process is gone is dropped rather than measured.
bool IsSessionProcessAlive(const TerminalSession& session);

// The verdict for one terminal. mqlMajor/dllBits are RESOLVED here (from the
// path and hash of the module that turned out to be ours), not supplied.
// terminalMachineIdHash is "-" when that process genuinely has no MachineId
// DLL loaded - the normal case, since nothing in the thin DLL loads it, and
// a file that is not loaded cannot affect anything.
struct SessionEvidence
{
    bool ok = false;
    std::string detail;  // why not ok - goes into the -2 failure report, never shown to the customer
    int mqlMajor = 0;
    int dllBits = 0;
    std::string eaHash;
    std::string dllHash;
    std::string terminalMachineIdHash;
};

SessionEvidence MeasureSession(const TerminalSession& session, const ManifestExpectations& expected);

// The Coordinator's own process: its running image plus the MachineId DLL it
// loaded itself (MachineIdBridge). Both are measured from live module
// handles, so neither can be a stale copy of something else.
struct HostEvidence
{
    bool ok = false;
    std::string detail;
    std::string brokerHash;
    std::string machineIdHash;
};

HostEvidence MeasureHost(
    const std::string& expectedBrokerHash,
    const std::string& expectedMachineIdHash);

} // namespace RuntimeMeasure
