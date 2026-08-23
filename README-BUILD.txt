NUTRICULA EXPERT ADVISOR INSTALLER
==================================

Technology
----------
C# + WinForms + .NET Framework 4.8

Project
-------
Open NutriculaInstaller.sln in Visual Studio 2022/2019 with .NET Framework 4.8 developer tools.
Build configuration: Release / Any CPU.

Required files before building
------------------------------
Place these files in the project's Assets folder with the EXACT names:

Nutricula.ex4
Nutricula.ex5
NutriculaLicenseCheck32.dll
NutriculaLicenseCheck64.dll
MachineId32.dll
MachineId64.dll
NutriculaLicenseService32.exe
NutriculaLicenseService64.exe
NutriculaLicenseBroker32.exe
NutriculaLicenseBroker64.exe
manifest.txt

Place icon.ico in the project root (next to NutriculaInstaller.csproj).

The eleven binary files are embedded as .NET resources, so the resulting installer does not need them beside the EXE. See README-GITHUB-BUILD.md for the full list and the GitHub Actions build path.

Important .NET Framework note
-----------------------------
The generated EXE is a single application file with all eleven product binaries embedded in it. .NET Framework 4.8 itself is an operating-system framework/runtime prerequisite; it is not copied beside the EXE.
Windows 7 SP1 systems may require .NET Framework 4.8 to be installed first.

Easy-to-change URLs
-------------------
InstallerService.cs contains:

PremiumUrl
TransferUrl

The two UI test URLs are in MainForm.cs:

https://www.youtube.com/
https://www.google.com/

Machine ID algorithm
--------------------
The deterministic Machine ID is SHA-256 over this exact UTF-8 canonical text, in this fixed order:

MACHINE_GUID=<normalized value>
BIOS_UUID=<normalized value>
BIOS_SERIAL=<normalized value>
BASEBOARD_SERIAL=<normalized value>
CPU_ID=<normalized value>
SYSTEM_DRIVE_SERIAL=<normalized value>

Normalization:
1. Null/whitespace-only -> empty string.
2. Trim leading/trailing whitespace.
3. Convert to invariant uppercase.
4. Collapse consecutive Unicode whitespace into one ASCII space.
5. Append the field exactly as KEY=VALUE followed by '\n'.
6. SHA-256 hash the resulting UTF-8 bytes.
7. Return uppercase hexadecimal.

Data sources:
- HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
- Win32_ComputerSystemProduct.UUID
- Win32_BIOS.SerialNumber
- Win32_BaseBoard.SerialNumber
- Win32_Processor.ProcessorId
- Win32_LogicalDisk.VolumeSerialNumber for the system drive

The implementation explicitly filters common placeholder WMI strings such as "To be filled by O.E.M.", "Default string", and "None".

Request/response protocol
--------------------------
NOTE: this section previously described an old AES-256-ECB protocol with a
hardcoded shared key - that description was stale and did not match the
actual client/server code even at the time it was written for this
version of the installer. The real, current protocol is:

- The entire request body (all fields together, not per-field) is
  encrypted with AES-256-GCM using the Transport Key from Keys/TransportKey.txt
  (see the Keys/ folder architecture and Keys_Reference.html).
- The envelope format is "N3:<base64(12-byte nonce || 16-byte GCM tag || ciphertext)>",
  sent as the single POST form field named "data".
- Every server response (Lease, Reject, and Challenge) is itself an
  RSA-4096/SHA-256 signed canonical string before being GCM-encrypted -
  signatures are verified client-side against the server's public key
  (LicenseCheck/ServerPublicKeyEmbedded.h) before any response is trusted.
  An unsigned or badly-signed response is always treated as Invalid.
- See LicenseCheck/LicenseProtocol.cpp/.h and PHP/license_common.php's
  nutricula_gcm_encrypt/nutricula_gcm_decrypt for the exact implementation.

MetaTrader discovery
--------------------
Discovery combines several sources:
- %APPDATA%\\MetaQuotes\\Terminal standard data directories
- running terminal.exe / terminal64.exe processes (portable/installation layout)
- Windows uninstall registry entries
- common program directories / local application data recursive executable search

Each detected MT4 and MT5 data directory is deduplicated independently and processed separately.
