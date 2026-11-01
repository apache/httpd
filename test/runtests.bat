@echo off
rem
rem runtests.bat -- run the Python test suites on Windows: modules/ and
rem pytest_suite/ in one pytest session against one built httpd.
rem
rem This is the Windows equivalent of runtests.sh.  It manages the .venv in
rem test\ so that pytest and the CGI helper scripts (which httpd forks) use the
rem same Python with all required packages, finds apxs/php-fpm/perl when it
rem can, and runs pytest from test\.
rem
rem Usage:
rem   runtests.bat --httpd C:\path\httpd.exe --conf C:\path\httpd.conf modules
rem   runtests.bat --apxs=C:\path\apxs pytest_suite\tests    -- the classic suite
rem   runtests.bat --httpd ... modules\http2                 -- a specific suite
rem   runtests.bat --httpd ... modules -k post -v            -- any pytest args pass through
rem
rem Name the suite to run: without a path both run, and pytest_suite\ has not
rem been exercised on Windows CI.  Paths are relative to test\.
rem
rem Environment overrides (used when the matching --flag is not supplied):
rem   PYTHON            path to python (auto-detected if not set)
rem   APXS              path to apxs
rem   HTTPD             path to httpd
rem   PHP_FPM           path to php-fpm
rem   APACHE_TEST_PERL  path to perl
rem

setlocal enabledelayedexpansion

set "HERE=%~dp0"
rem Remove trailing backslash
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"
set "PROJ=%HERE%"

rem --- python location: find the newest native Windows Python 3.x -------------
if not defined PYTHON (
    set PYTHON=
    for /f "delims=" %%P in ('where python.exe 2^>nul') do (
        if not defined PYTHON (
            echo %%P | findstr /i "hostedtoolcache" >nul
            if not errorlevel 1 set "PYTHON=%%P"
        )
    )
)
if not defined PYTHON (
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
set "PYTEST=%PROJ%\.venv\Scripts\pytest.exe"

set "NEED_SYNC=0"
if not exist "%PYTEST%" set "NEED_SYNC=1"

rem Check if pyproject.toml is newer than .venv (approximate: compare timestamps
rem via xcopy /D /L which lists files that are newer than the destination).
if exist "%PROJ%\.venv" (
    for /f %%F in ('xcopy /D /L /Y "%PROJ%\pyproject.toml" "%PROJ%\.venv\" 2^>nul ^| C:\Windows\System32\find.exe /c "pyproject.toml"') do (
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
    echo runtests.bat: ^(re^)creating %PROJ%\.venv via 'uv sync'... >&2
    %PYTHON% -m uv sync --project "%PROJ%"
    if errorlevel 1 exit /b 1
    rem Touch .venv so the staleness check won't retrigger
    copy /b "%PROJ%\.venv" +,, "%PROJ%\.venv" >nul 2>&1
)

rem --- discover apxs / php-fpm / perl -----------------------------------------
if not defined APXS (
    for %%C in (apxs.exe) do (
        if "!APXS!"=="" (
            for /f "delims=" %%P in ('where %%C 2^>nul') do (
                if "!APXS!"=="" set "APXS=%%P"
            )
        )
    )
)

if not defined PHP_FPM (
    for %%C in (php-fpm.exe php-fpm8.3.exe php-fpm83.exe php-fpm8.2.exe php-fpm82.exe) do (
        if "!PHP_FPM!"=="" (
            for /f "delims=" %%P in ('where %%C 2^>nul') do (
                if "!PHP_FPM!"=="" set "PHP_FPM=%%P"
            )
        )
    )
)

if not defined APACHE_TEST_PERL (
    for %%C in (perl.exe) do (
        for /f "delims=" %%P in ('where %%C 2^>nul') do (
            if "!APACHE_TEST_PERL!"=="" set "APACHE_TEST_PERL=%%P"
        )
    )
)

rem Build the default flag set only for values the user did not pass explicitly.
set "AUTO_ARGS="

set "HAS_SERVER_FLAG=0"
for %%A in (%*) do (
    echo %%A | findstr /b /c:"--apxs" /c:"--httpd" >nul 2>&1 && set "HAS_SERVER_FLAG=1"
)

if "%HAS_SERVER_FLAG%"=="0" (
    if defined APXS (
        set "AUTO_ARGS=--apxs=!APXS!"
    ) else if defined HTTPD (
        set "AUTO_ARGS=--httpd=!HTTPD!"
    ) else (
        echo runtests.bat: note: no apxs/httpd given or found; using the build of >&2
        echo   pyhttpd\config.ini ^(or PYHTTPD_CONFIG^) if there is one. >&2
    )
)

set "HAS_PHP_FLAG=0"
for %%A in (%*) do (
    echo %%A | findstr /b /c:"--php-fpm" >nul 2>&1 && set "HAS_PHP_FLAG=1"
)

if "%HAS_PHP_FLAG%"=="0" (
    if defined PHP_FPM (
        set "AUTO_ARGS=!AUTO_ARGS! --php-fpm=!PHP_FPM!"
    ) else (
        echo runtests.bat: note: no php-fpm found; PHP tests will skip. >&2
        echo   Set PHP_FPM=C:\path\to\php-fpm to run them. >&2
    )
)

set "HAS_PERL_FLAG=0"
for %%A in (%*) do (
    echo %%A | findstr /b /c:"--with-perl" >nul 2>&1 && set "HAS_PERL_FLAG=1"
)

if "%HAS_PERL_FLAG%"=="0" (
    if defined APACHE_TEST_PERL (
        set "AUTO_ARGS=!AUTO_ARGS! --with-perl=!APACHE_TEST_PERL!"
    ) else (
        echo runtests.bat: note: no perl found; rewrite prg-map tests may fail. >&2
        echo   Pass --with-perl=C:\path\to\perl.exe or set APACHE_TEST_PERL=... >&2
    )
)

rem A stale mod_cgid socket in the classic suite's t\logs can break a fresh run.
del /q "%HERE%\pytest_suite\t\logs\cgisock*" 2>nul

rem --- Windows-specific exclusions --------------------------------------------
set "WIN_IGNORE=--ignore=modules\md"
set "WIN_SKIP=not test_800_websockets and not test_02_unix"

rem --- run, from test\ ----------------------------------------------------------
cd /d "%HERE%"
echo runtests.bat: "%PYTEST%" %AUTO_ARGS% %WIN_IGNORE% -k "%WIN_SKIP%" %* >&2
"%PYTEST%" %AUTO_ARGS% %WIN_IGNORE% -k "%WIN_SKIP%" %*
exit /b %errorlevel%
