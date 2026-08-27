@echo off
rem
rem runtests.bat -- run the pyhttpd modules/ test suite on Windows.
rem
rem This is the Windows equivalent of runtests.sh.  It manages a local .venv
rem under pyhttpd/ so that pytest and the CGI helper scripts (which httpd
rem forks) both use the same Python with all required packages.
rem
rem Usage:
rem   runtests.bat --httpd C:\path\httpd.exe --conf C:\path\httpd.conf
rem   runtests.bat --httpd ... modules\http2     -- run a specific suite
rem   runtests.bat --httpd ... -k post -v        -- any pytest args pass through
rem
rem Environment overrides:
rem   PYTHON     path to python (auto-detected if not set)
rem   PYHTTPD_TARGETS  space-separated list of test paths (default: modules)
rem

setlocal enabledelayedexpansion

set "HERE=%~dp0"
rem Remove trailing backslash
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

rem --- python location: find the newest native Windows Python 3.x -------------
if not defined PYTHON (
    set PYTHON=
    for /f "delims=" %%D in ('dir /b /o-n "%LOCALAPPDATA%\Programs\Python\Python3*" 2^>nul') do (
        if not defined PYTHON set "PYTHON=%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
    )
)
if not defined PYTHON (
    for /f "delims=" %%D in ('dir /b /o-n "%PROGRAMFILES%\Python3*" 2^>nul') do (
        if not defined PYTHON set "PYTHON=%PROGRAMFILES%\%%D\python.exe"
    )
)
if not defined PYTHON (
    echo runtests.bat: ERROR: Python interpreter not found. >&2
    echo   Install Python from https://www.python.org or set PYTHON=... >&2
    exit /b 1
)

rem --- ensure the venv exists and is current ----------------------------------
set "PYTEST=%HERE%\.venv\Scripts\pytest.exe"

set "NEED_SYNC=0"
if not exist "%PYTEST%" set "NEED_SYNC=1"

if exist "%HERE%\.venv" (
    for /f %%F in ('xcopy /D /L /Y "%HERE%\pyproject.toml" "%HERE%\.venv\" 2^>nul ^| C:\Windows\System32\find.exe /c "pyproject.toml"') do (
        if %%F gtr 0 set "NEED_SYNC=1"
    )
) else (
    set "NEED_SYNC=1"
)

if "%NEED_SYNC%"=="1" (
    %PYTHON% -m uv --version >nul 2>&1
    if errorlevel 1 (
        echo runtests.bat: ERROR: 'uv' is required but not installed. >&2
        echo   Install it from https://docs.astral.sh/uv/ and re-run. >&2
        echo   %PYTHON% -m pip install uv >&2
        exit /b 1
    )
    echo runtests.bat: ^(re^)creating %HERE%\.venv via 'uv sync'... >&2
    %PYTHON% -m uv sync --project "%HERE%"
    if errorlevel 1 exit /b 1
    copy /b "%HERE%\.venv" +,, "%HERE%\.venv" >nul 2>&1
)

rem --- run from test/ (parent of pyhttpd/) ------------------------------------
cd /d "%HERE%\.."

rem --- default target ----------------------------------------------------------
if defined PYHTTPD_TARGETS (
    set "TARGETS=%PYHTTPD_TARGETS%"
) else (
    set "TARGETS=modules"
)

rem --- Windows-specific exclusions --------------------------------------------
set "WIN_IGNORE=--ignore=modules\md"
set "WIN_SKIP=not test_cgi_003_01 and not test_800_websockets and not test_02_unix and not test_003_get and not test_004_post and not test_002_restarts and not test_005_trailers and not test_h2_601"

echo runtests.bat: "%PYTEST%" %WIN_IGNORE% -k "%WIN_SKIP%" %TARGETS% %* >&2
"%PYTEST%" %WIN_IGNORE% -k "%WIN_SKIP%" %TARGETS% %*
exit /b %errorlevel%
