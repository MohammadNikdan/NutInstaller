# Nutricula Installer — GitHub Actions Build

This repository is prepared for building the Nutricula Expert Advisor Installer online with GitHub Actions.

## Required files

Put these files in the exact locations below before starting the build:

```text
icon.ico
Assets/Nutricula.ex4
Assets/Nutricula.ex5
Assets/NutriculaLicenseCheck32.dll
Assets/NutriculaLicenseCheck64.dll
Assets/MachineId32.dll
Assets/MachineId64.dll
Assets/NutriculaLicenseBroker32.exe
Assets/NutriculaLicenseBroker64.exe
Assets/manifest.txt
```

The eleven files under `Assets` are compiled into the installer as embedded .NET resources. They are **not** copied beside the final EXE.

`icon.ico` is used as the application's Windows icon through the project `ApplicationIcon` setting.

## Online build

1. Create a GitHub repository. A **Private** repository is strongly recommended because the project contains proprietary binaries and the client-side protocol key.
2. Upload the complete project contents to the repository root.
3. Confirm the twelve required files exist at the exact paths above.
4. Open **Actions** in GitHub.
5. Select **1. Windows - 32bit** (the Windows installer). For the Mac and Linux packages also run, separately, **2. Windows - 32bit (for Mac/Linux)** and **3. Windows - 64bit (for Mac/Linux)**.
6. Press **Run workflow**.
7. When a workflow finishes successfully, open the workflow run and download its artifact:
   - **Nutricula-Unsigned-32bit** (from *1. Windows - 32bit*) - one file, `Nutricula-Unsigned-32bit.exe`.
   - **Nutricula-Unsigned-32bit-SC** (from *2. Windows - 32bit (for Mac/Linux)*) - one file, `Nutricula-Unsigned-32bit-SC.zip`.
   - **Nutricula-Unsigned-64bit-SC** (from *3. Windows - 64bit (for Mac/Linux)*) - one file, `Nutricula-Unsigned-64bit-SC.zip`.

("SC" = self-contained: workflows 2 and 3 build an installer that carries its own .NET runtime, because the copy of Wine that ships with MetaTrader 5 on a Mac has no .NET Framework in it. They are only ever bundled into the Mac / Linux packages, never given to Windows users.)

**The two `-SC` zips are not finished installers, and they never become a single exe.** Each one is a whole self-contained PUBLISH FOLDER: the native apphost `NutriculaExpertInstaller.exe`, the managed `NutriculaExpertInstaller.dll` beside it, and dozens of .NET runtime files (`coreclr.dll`, `hostfxr.dll`, `System.*.dll`, ...). Extract the zip before doing anything else with it. Neither ConfuserEx nor .NET Reactor can merge those native runtime files into one exe - ConfuserEx cannot open this kind of build at all (it only understands a single plain managed assembly), and .NET Reactor's own merge/embed-assemblies features only operate on managed .NET assemblies, never on native DLLs. So the folder itself ships, essentially unchanged, with only its one managed assembly protected.

Next, on the secure build machine, the three flavours are protected differently:

- **`Nutricula-Unsigned-32bit.exe`** (the Windows installer): run it through **ConfuserEx** exactly as before.
- **Each extracted `-SC` folder**: run **ONLY** the folder's `NutriculaExpertInstaller.dll` through **.NET Reactor**, with **`-target_runtime dotnet`** explicitly set (this is a .NET 8 assembly, not classic .NET Framework/Mono - Reactor must be told so). Recommended settings, matching what was previously used with ConfuserEx:
  - Control Flow Obfuscation: **ON** (`flow_level 9`, engine `massive` - Reactor's defaults)
  - Anti Tampering: **OFF**
  - Obfuscation (renaming): **ON**
  - String Encryption: **ON**
  - Resource Encryption & Compression: **OFF** (this is what caused the slow installer startup previously seen with ConfuserEx's "resources" option - leave it off here too)
  - NecroBit / Code Virtualization / Native EXE File: leave **OFF** unless you have specifically tested the installer still works correctly with them on
  Point Reactor's output back at the same `NutriculaExpertInstaller.dll` path inside the extracted folder (overwriting the plain one) - every other file in the folder (the apphost exe, every native/managed runtime file) is left exactly as `dotnet publish` produced it.

Then sign with `NutriculaSignInstaller.exe`. It now handles both kinds of flavour automatically, no manual path or renaming needed - the only difference is WHERE you put/run it:

- **For `Nutricula-Unsigned-32bit.exe`** (the Windows installer): place it next to `NutriculaSignInstaller.exe`, run the tool with no arguments (double-click it), confirm. It is signed and renamed to `Nutricula-32bit.exe`. (Unchanged from before.)
- **For each extracted `-SC` folder**: copy `NutriculaSignInstaller.exe` **into that same folder** (right beside its own `NutriculaExpertInstaller.exe`), then run it there with no arguments, confirm. It reads the apphost exe's own PE header to tell 32-bit from 64-bit automatically (never guessed from a name or the folder's name), signs it, and renames **all four** of `NutriculaExpertInstaller.{exe,dll,deps.json,runtimeconfig.json}` together to `Nutricula-{32,64}bit-SC.*` - so you can see at a glance that it worked. (Renaming only the exe would break the self-contained app: it finds its companion `.dll` / `.deps.json` / `.runtimeconfig.json` by matching its own file name exactly - this is why all four are renamed in one step, never just one.)

(Scripted/automated use is still available and works the same way for either flavour: `NutriculaSignInstaller.exe <path_to_an_exe>` - it detects which kind of file it was given on its own.)

Resulting files/folders:

```text
Nutricula-32bit.exe      <- the Windows installer for ALL Windows users (32- and 64-bit Windows)
Nutricula-32bit-SC/      <- the WHOLE extracted folder (protected dll + signed exe + untouched
                            runtime files) - only bundled into the Mac / Linux packages
Nutricula-64bit-SC/      <- same, the 64-bit flavour's whole folder
```

Put the **two whole `-SC` folders** (not single files) into the repo's `dist/` folder, under exactly the names `dist/Nutricula-32bit-SC/` and `dist/Nutricula-64bit-SC/`, then run **4. Mac** and **5. Linux** (they produce `Nutricula.dmg` and `Nutricula.AppImage`, copying each folder's full contents into its own per-architecture subfolder inside the package). The Windows installer `Nutricula-32bit.exe` is not used by those two workflows.

Workflow 1 uses a Windows Server 2022 GitHub-hosted runner and MSBuild. GitHub's Windows 2022 image includes Visual Studio 2022, MSBuild, and .NET Framework 4.8 targeting/build components. Workflows 2 and 3 use the same runner with its pre-installed .NET SDK (8 or newer, checked at the start of the run) and build `SelfContained/NutriculaInstaller.SelfContained.csproj`, which compiles the very same source files and embeds the very same resources as `NutriculaInstaller.csproj` (each run checks that the two project files still list identical items - if you add or remove a source file or an embedded resource in one, mirror it in the other). They publish it as a plain self-contained FOLDER (`PublishSingleFile=false`), not a single file - that folder is what ships, with only its managed `.dll` protected by .NET Reactor afterwards (see above); it is never bundled into a single exe by anything in this pipeline.

## Important

The generated installer is a single application EXE containing the eleven Nutricula product binaries as embedded resources. For the Windows installer (workflow 1), .NET Framework 4.8 itself remains an operating-system/runtime prerequisite and is not embedded into the EXE. The two self-contained Mac/Linux builds (workflows 2 and 3) are different: they embed their own .NET runtime, which is why they are much larger.

The build workflow intentionally fails before compilation if any required file is missing.

## Local build

A local Visual Studio installation is not required for the GitHub build. The `.sln` and `NutriculaInstaller.csproj` are standard .NET Framework 4.8 MSBuild projects (the Windows installer). `SelfContained/NutriculaInstaller.SelfContained.csproj` is the separate .NET 8 project for the Mac/Linux builds; it is built only through its workflows.
