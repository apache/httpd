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
