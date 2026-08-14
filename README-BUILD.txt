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
Nutricula.ex4.sig
Nutricula.ex5.sig
MathUtils.dll

Place icon.ico in the project root (next to NutriculaInstaller.csproj).

The five binary files are embedded as .NET resources, so the resulting installer does not need them beside the EXE.

Important .NET Framework note
-----------------------------
The generated EXE is a single application file with all five product binaries embedded in it. .NET Framework 4.8 itself is an operating-system framework/runtime prerequisite; it is not copied beside the EXE.
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

AES request compatibility
-------------------------
The request encoder uses:
- key: lj1@91!23867871jbhlk*&GS^madf^&!
- AES-256
- ECB
- Zero padding
- UTF-8 input bytes
- uppercase hexadecimal ciphertext

The request is built exactly in this order:

rnd_number=<Encoder(rnd_number)>&email=<email>&purchase_key=<purchase_key>&machine_id=<Encoder(machine_id)>

Then the complete PostData is passed through Encoder() once more and sent as the data query parameter.

Response handling
-----------------
The response is read as raw response bytes.
The decoded response text is compared exactly to "no" using StringComparison.Ordinal.
If it is "no", the old NutriculaLicense.txt is deleted and no replacement is written.
For any other response, the ORIGINAL BYTES are written directly to NutriculaLicense.txt without trim, parse, decrypt, decode/re-encode or transformation.

MetaTrader discovery
--------------------
Discovery combines several sources:
- %APPDATA%\\MetaQuotes\\Terminal standard data directories
- running terminal.exe / terminal64.exe processes (portable/installation layout)
- Windows uninstall registry entries
- common program directories / local application data recursive executable search

Each detected MT4 and MT5 data directory is deduplicated independently and processed separately.
