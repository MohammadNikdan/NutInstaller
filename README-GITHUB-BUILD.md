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
   - **Nutricula-Unsigned-32bit** (from *1. Windows - 32bit*)
   - **Nutricula-Unsigned-32bit-SC** (from *2. Windows - 32bit (for Mac/Linux)*)
   - **Nutricula-Unsigned-64bit-SC** (from *3. Windows - 64bit (for Mac/Linux)*)

Each downloaded artifact contains one file:

```text
Nutricula-Unsigned-32bit.exe
Nutricula-Unsigned-32bit-SC.exe
Nutricula-Unsigned-64bit-SC.exe
```

("SC" = self-contained: workflows 2 and 3 build an installer that carries its own .NET runtime inside the exe, because the copy of Wine that ships with MetaTrader 5 on a Mac has no .NET Framework in it. They are only ever bundled into the Mac / Linux packages, never given to Windows users.)

Next, on the secure build machine: run `Nutricula-Unsigned-32bit.exe` through ConfuserEx as before. **The two "-SC" files cannot be run through ConfuserEx**: a self-contained exe is a native launcher with the .NET assemblies bundled inside it, which ConfuserEx cannot open - so for now they are signed but not obfuscated. Then put the file(s) next to `NutriculaSignInstaller.exe` and run it. It finds each flavour by name, signs it, and produces the final files:

```text
Nutricula-32bit.exe      <- the Windows installer for ALL Windows users (32- and 64-bit Windows)
Nutricula-32bit-SC.exe   <- only bundled into the Mac / Linux packages, never given to Windows users
Nutricula-64bit-SC.exe   <- only bundled into the Mac / Linux packages, never given to Windows users
```

Put the **two "-SC" files** into the repo's `dist/` folder, then run **4. Mac** and **5. Linux** (they produce `Nutricula.dmg` and `Nutricula.AppImage`). The Windows installer `Nutricula-32bit.exe` is not used by those two workflows.

Workflow 1 uses a Windows Server 2022 GitHub-hosted runner and MSBuild. GitHub's Windows 2022 image includes Visual Studio 2022, MSBuild, and .NET Framework 4.8 targeting/build components. Workflows 2 and 3 use the same runner with its pre-installed .NET SDK (8 or newer, checked at the start of the run) and build `SelfContained/NutriculaInstaller.SelfContained.csproj`, which compiles the very same source files and embeds the very same resources as `NutriculaInstaller.csproj` (each run checks that the two project files still list identical items - if you add or remove a source file or an embedded resource in one, mirror it in the other).

## Important

The generated installer is a single application EXE containing the eleven Nutricula product binaries as embedded resources. For the Windows installer (workflow 1), .NET Framework 4.8 itself remains an operating-system/runtime prerequisite and is not embedded into the EXE. The two self-contained Mac/Linux builds (workflows 2 and 3) are different: they embed their own .NET runtime, which is why they are much larger.

The build workflow intentionally fails before compilation if any required file is missing.

## Local build

A local Visual Studio installation is not required for the GitHub build. The `.sln` and `NutriculaInstaller.csproj` are standard .NET Framework 4.8 MSBuild projects (the Windows installer). `SelfContained/NutriculaInstaller.SelfContained.csproj` is the separate .NET 8 project for the Mac/Linux builds; it is built only through its workflows.
