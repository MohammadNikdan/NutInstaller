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
Assets/NutriculaLicenseService32.exe
Assets/NutriculaLicenseService64.exe
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
5. Select **Build Nutricula Installer**.
6. Press **Run workflow**.
7. When the workflow finishes successfully, open the workflow run and download the artifact named **NutriculaExpertInstaller**.

The downloaded artifact contains:

```text
NutriculaExpertInstaller.exe
```

The workflow uses a Windows Server 2022 GitHub-hosted runner and MSBuild. GitHub's Windows 2022 image includes Visual Studio 2022, MSBuild, and .NET Framework 4.8 targeting/build components.

## Important

The generated installer is a single application EXE containing the eleven Nutricula product binaries as embedded resources. .NET Framework 4.8 itself remains an operating-system/runtime prerequisite and is not embedded into this EXE.

The build workflow intentionally fails before compilation if any required file is missing.

## Local build

A local Visual Studio installation is not required for the GitHub build. The `.sln` and `.csproj` are standard .NET Framework 4.8 MSBuild projects.
