paste BOTH signed self-contained installer FOLDERS here (not single exe files) to build the
Mac & Linux versions:
  Nutricula-32bit-SC/   (from workflow "2. Windows - 32bit (for Mac/Linux)": extract its zip,
                         protect ONLY NutriculaExpertInstaller.dll inside it with .NET Reactor,
                         then copy NutriculaSignInstaller.exe into that same folder and run it
                         there with no arguments - it reads the apphost's own PE header and
                         signs NutriculaExpertInstaller.exe IN PLACE, under its original name
                         (it is never renamed - neither it nor its 3 companions
                         .dll/.deps.json/.runtimeconfig.json - because the apphost's own
                         managed-assembly reference is baked in at publish time and does not
                         survive a rename) - then place the WHOLE folder here under this name)
  Nutricula-64bit-SC/   (from workflow "3. Windows - 64bit (for Mac/Linux)", same as above)

Each folder must still contain everything dotnet publish produced (the signed apphost exe,
still named NutriculaExpertInstaller.exe, + managed dll + its .deps.json/.runtimeconfig.json,
and the dozens of .NET runtime files beside them, untouched) - the Mac and Linux workflows look
for NutriculaExpertInstaller.exe/.dll specifically inside each folder, so don't rename anything.

(Nutricula-32bit.exe - the Windows installer - is not used by the Mac/Linux workflows. It goes
through ConfuserEx as before, not .NET Reactor, and stays a single file.)
