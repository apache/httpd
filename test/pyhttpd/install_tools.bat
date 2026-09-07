@echo off
rem
rem install_tools.bat -- install curl CLI and nghttp2 for pyhttpd tests.
rem
rem Usage:
rem   install_tools.bat C:\path\to\httpd\prefix
rem
rem Uses vcpkg to install curl (with CLI tool) and nghttp2, then copies
rem binaries into the httpd prefix bin/ directory so the test framework
rem can find them.
rem

setlocal enabledelayedexpansion

set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
pushd "%HERE%\.."
set "TEST_DIR=%CD%"
popd

rem --- target prefix (where httpd is installed) -------------------------------
if not "%~1"=="" (
    set "PREFIX=%~1"
) else (
    echo install_tools.bat: ERROR: specify the httpd install prefix as argument. >&2
    echo   Example: install_tools.bat "C:\Program Files (x86)\APR" >&2
    exit /b 1
)

if not exist "%PREFIX%\bin\httpd.exe" (
    echo install_tools.bat: ERROR: httpd.exe not found in "%PREFIX%\bin". >&2
    echo   Is "%PREFIX%" the correct httpd install prefix? >&2
    exit /b 1
)

rem --- python detection and install --------------------------------------------
set PYTHON=
for /f "delims=" %%D in ('dir /b /o-n "%LOCALAPPDATA%\Programs\Python\Python3*" 2^>nul') do (
    if not defined PYTHON set "PYTHON=%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
)
if not defined PYTHON (
    for /f "delims=" %%D in ('dir /b /o-n "%PROGRAMFILES%\Python3*" 2^>nul') do (
        if not defined PYTHON set "PYTHON=%PROGRAMFILES%\%%D\python.exe"
    )
)
if defined PYTHON (
    echo install_tools.bat: Python found at "!PYTHON!" >&2
    goto :python_ok
)

echo install_tools.bat: Python not found, installing... >&2
rem Query the Python API for the latest stable release and extract the version
set "PY_VERSION="
curl -s -o "%TEMP%\pyrel.json" "https://www.python.org/api/v2/downloads/release/?is_published=true&pre_release=false&version=3"
for /f "delims=" %%V in ('powershell -NoProfile -Command "$ProgressPreference='SilentlyContinue'; $j = Get-Content '%TEMP%\pyrel.json' -Raw | ConvertFrom-Json; ($j | Where-Object { $_.is_latest -eq $true }).name -replace 'Python ', ''" 2^>nul') do (
    set "PY_VERSION=%%V"
)
del "%TEMP%\pyrel.json" 2>nul
if not defined PY_VERSION (
    echo install_tools.bat: ERROR: could not detect latest Python version. >&2
    echo   Install Python manually from https://www.python.org/downloads/windows/ >&2
    exit /b 1
)
echo install_tools.bat: latest Python version: %PY_VERSION% >&2

set "PY_INSTALLER=python-%PY_VERSION%-amd64.exe"
set "PY_URL=https://www.python.org/ftp/python/%PY_VERSION%/%PY_INSTALLER%"
echo install_tools.bat: downloading %PY_URL%... >&2
curl -L -o "%TEMP%\%PY_INSTALLER%" "%PY_URL%"
if errorlevel 1 (
    echo install_tools.bat: ERROR: download failed. >&2
    exit /b 1
)

echo install_tools.bat: installing Python %PY_VERSION%... >&2
"%TEMP%\%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=0 Include_launcher=0
if errorlevel 1 (
    echo install_tools.bat: ERROR: Python installation failed. >&2
    exit /b 1
)
del "%TEMP%\%PY_INSTALLER%" 2>nul

rem Re-detect after install
set PYTHON=
for /f "delims=" %%D in ('dir /b /o-n "%LOCALAPPDATA%\Programs\Python\Python3*" 2^>nul') do (
    if not defined PYTHON set "PYTHON=%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
)
if not defined PYTHON (
    echo install_tools.bat: ERROR: Python still not found after install. >&2
    exit /b 1
)
echo install_tools.bat: Python installed at "!PYTHON!" >&2

:python_ok

rem --- uv detection and install ------------------------------------------------
"!PYTHON!" -m uv --version >nul 2>&1
if not errorlevel 1 (
    echo install_tools.bat: uv already installed. >&2
    goto :uv_ok
)
echo install_tools.bat: uv not found, installing via pip... >&2
"!PYTHON!" -m pip install uv
if errorlevel 1 (
    echo install_tools.bat: ERROR: failed to install uv. >&2
    exit /b 1
)
"!PYTHON!" -m uv --version >nul 2>&1
if errorlevel 1 (
    echo install_tools.bat: ERROR: uv still not working after install. >&2
    exit /b 1
)
echo install_tools.bat: uv installed successfully. >&2

:uv_ok

rem --- perl detection and install (Strawberry Perl) ----------------------------
set PERL=
for /f "delims=" %%P in ('where perl.exe 2^>nul') do (
    if not defined PERL set "PERL=%%P"
)
if not defined PERL (
    if exist "C:\Strawberry\perl\bin\perl.exe" set "PERL=C:\Strawberry\perl\bin\perl.exe"
)
if defined PERL (
    echo install_tools.bat: Perl found at "!PERL!" >&2
    goto :perl_ok
)

echo install_tools.bat: Perl not found, installing Strawberry Perl... >&2
rem Get the latest 64bit.msi download URL from GitHub releases API
set "PERL_URL="
for /f "tokens=2 delims= " %%U in ('curl -s https://api.github.com/repos/StrawberryPerl/Perl-Dist-Strawberry/releases/latest ^| findstr /i "browser_download_url.*64bit.msi"') do (
    if not defined PERL_URL set "PERL_URL=%%~U"
)
if not defined PERL_URL (
    echo install_tools.bat: ERROR: could not detect latest Strawberry Perl installer. >&2
    echo   Install Perl manually from https://strawberryperl.com >&2
    exit /b 1
)
for %%F in ("%PERL_URL%") do set "PERL_MSI=%%~nxF"
echo install_tools.bat: downloading %PERL_URL%... >&2
curl -L -o "%TEMP%\%PERL_MSI%" "%PERL_URL%"
if errorlevel 1 (
    echo install_tools.bat: ERROR: download failed. >&2
    exit /b 1
)

echo install_tools.bat: installing Strawberry Perl %PERL_VERSION%... >&2
msiexec /i "%TEMP%\%PERL_MSI%" /quiet /norestart INSTALLDIR="C:\Strawberry"
if errorlevel 1 (
    echo install_tools.bat: ERROR: Strawberry Perl installation failed. >&2
    exit /b 1
)
del "%TEMP%\%PERL_MSI%" 2>nul

rem Re-detect after install
set PERL=
if exist "C:\Strawberry\perl\bin\perl.exe" (
    set "PERL=C:\Strawberry\perl\bin\perl.exe"
    set "PATH=C:\Strawberry\perl\bin;C:\Strawberry\c\bin;!PATH!"
)
if not defined PERL (
    echo install_tools.bat: ERROR: Perl still not found after install. >&2
    exit /b 1
)
echo install_tools.bat: Strawberry Perl installed at "!PERL!" >&2

:perl_ok

rem --- vcpkg location ---------------------------------------------------------
set "VCPKG_DIR=%TEST_DIR%\vcpkg"
set "VCPKG_TRIPLET=x64-windows"
set "VCPKG_INSTALLED=%VCPKG_DIR%\installed\%VCPKG_TRIPLET%"

rem --- bootstrap vcpkg if needed ----------------------------------------------
if not exist "%VCPKG_DIR%\" (
    echo install_tools.bat: cloning vcpkg... >&2
    git clone https://github.com/microsoft/vcpkg.git "%VCPKG_DIR%"
    if errorlevel 1 (
        echo install_tools.bat: ERROR: git clone failed. >&2
        exit /b 1
    )
) else (
    echo install_tools.bat: vcpkg already present, updating... >&2
    pushd "%VCPKG_DIR%"
    git pull
    popd
)

if not exist "%VCPKG_DIR%\vcpkg.exe" (
    echo install_tools.bat: bootstrapping vcpkg... >&2
    pushd "%VCPKG_DIR%"
    icacls scripts\tls12-download.exe /grant "%USERNAME%":RX >nul 2>&1
    call bootstrap-vcpkg.bat
    if errorlevel 1 (
        popd
        echo install_tools.bat: ERROR: vcpkg bootstrap failed. >&2
        exit /b 1
    )
    popd
)

icacls "%VCPKG_DIR%\vcpkg.exe" /grant "%USERNAME%":RX >nul 2>&1
set "VCPKG_EXE=%VCPKG_DIR%\vcpkg.exe"

rem --- install packages -------------------------------------------------------
echo install_tools.bat: installing curl[core,tool,http2,openssl] and nghttp2 via vcpkg... >&2
"%VCPKG_EXE%" install --recurse --triplet %VCPKG_TRIPLET% curl[core,tool,http2,openssl] nghttp2
if errorlevel 1 (
    echo install_tools.bat: ERROR: vcpkg install failed. >&2
    exit /b 1
)

rem --- copy binaries to httpd prefix ------------------------------------------
echo install_tools.bat: copying binaries to "%PREFIX%\bin"... >&2

if exist "%VCPKG_INSTALLED%\tools\curl\curl.exe" (
    copy /y "%VCPKG_INSTALLED%\tools\curl\curl.exe" "%PREFIX%\bin\" >nul
    echo   curl.exe installed >&2
) else (
    echo   WARNING: curl.exe not found in vcpkg output >&2
    dir /s /b "%VCPKG_INSTALLED%\*curl*.exe" 2>nul
)

rem Copy all supporting DLLs (curl needs libcurl, openssl, zlib, nghttp2, etc.)
if exist "%VCPKG_INSTALLED%\bin\*.dll" (
    copy /y "%VCPKG_INSTALLED%\bin\*.dll" "%PREFIX%\bin\" >nul
    echo   vcpkg DLLs copied >&2
)

rem --- verify -----------------------------------------------------------------
if exist "%PREFIX%\bin\curl.exe" (
    echo install_tools.bat: verifying curl: >&2
    "%PREFIX%\bin\curl.exe" --version
) else (
    echo install_tools.bat: WARNING: curl.exe was not installed. >&2
    exit /b 1
)

echo install_tools.bat: done. >&2
exit /b 0
