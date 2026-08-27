@echo off
setlocal
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" (
    echo ERROR: 64-bit .NET Framework C# compiler not found:
    echo %CSC%
    echo Install/enable .NET Framework 4.x or build the .csproj in Visual Studio.
    pause
    exit /b 1
)

echo Building CivicJ2534CanSniffer-v2.2-x64.exe ...
"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ ^
 /out:"CivicJ2534CanSniffer-v2.2-x64.exe" ^
 /reference:System.dll ^
 /reference:System.Core.dll ^
 /reference:System.Drawing.dll ^
 /reference:System.Windows.Forms.dll ^
 "CivicJ2534CanSniffer.cs"

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo BUILD OK: %CD%\CivicJ2534CanSniffer-v2.2-x64.exe
pause
