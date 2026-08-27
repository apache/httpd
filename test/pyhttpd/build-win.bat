@ECHO off
@REM

@REM -------------------------------------
@REM Variables used in this script
@REM -------------------------------------
SET CWD=%CD%
SET "CWD=%CWD:\=/%"
@REM -------------------------------------
SET ARCH="x64-windows"
SET BUILD_TYPE="Debug"
SET VCPKG_DIRECTORY="vcpkg\installed\x64-windows"
SET VCPKG_DIRECTORY_LIB=%VCPKG_DIRECTORY%
SET GENERATOR="NMake Makefiles"
@REM SET GENERATOR="Ninja"
SET CMAKE_VERSION="4.0"
SET HTTPD_INSTALL_DIRECTORY="C:/Users/%USERNAME%/Projects/http-debug/apache"
@REM -------------------------------------

@REM -------------------------------------
@REM Installs via MS vcpkg manager all the 
@REM packages needed to build httpd
@REM -------------------------------------
if NOT EXIST vcpkg\ (
    echo "Adding...."
    git submodule add --force https://github.com/microsoft/vcpkg.git vcpkg
    PUSHD vcpkg\
    CALL bootstrap-vcpkg.bat
) else (
    echo "Updating...."
    git submodule update --remote --merge vcpkg\
    PUSHD vcpkg\
)

SET VCPKG_ROOT=%CWD%\vcpkg
@REM For some reason using the manifest doesn't install the default-features
vcpkg.exe install --triplet x64-windows apr[private-headers] apr-util pcre2 openssl nghttp2 curl libxml2 jansson

POPD

@REM -------------------------------------
@REM Setup build env using VS build 2022
@REM It maybe installed somewhere else, if so, the path will need updating to find the batch file
@REM -------------------------------------
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

@REM -------------------------------------
@REM Create a temp dir for cmake files
@REM -------------------------------------
if not EXIST build-asf-win\ (
    mkdir build-asf-win\
) 

PUSHD build-asf-win\

@REM -------------------------------------
@REM Run cmake so that it configures the
@REM and creates the needed makefiles
@REM -------------------------------------
cmake .. -B . ^
    -G %GENERATOR% ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_TOOLCHAIN_FILE=%CWD%/vcpkg/scripts/buildsystems/vcpkg.cmake ^
    -DVCPKG_TARGET_TRIPLET=%ARCH% ^
    -DNGHTTP2_INCLUDE_DIR=%CWD%/vcpkg/installed/x64-windows/include ^
    -DAPR_INCLUDE_DIR=%CWD%/vcpkg/installed/x64-windows/include ^
    -DJANSSON_INCLUDE_DIR=%CWD%/vcpkg/installed/x64-windows/include ^
    "-DAPR_LIBRARIES=%CWD%/vcpkg/installed/x64-windows/lib/libapr-1.lib;%CWD%/vcpkg/installed/x64-windows/lib/libaprutil-1.lib" ^
    -DNGHTTP2_LIBRARIES=%CWD%/vcpkg/installed/x64-windows/lib/nghttp2.lib ^
    -DJANSSON_LIBRARIES=%CWD%/vcpkg/installed/x64-windows/lib/jansson.lib ^
    -DBUILD_PYHTTPD_MODULES=true ^
    -DCMAKE_POLICY_VERSION_MINIMUM=%CMAKE_VERSION% ^
    --install-prefix %HTTPD_INSTALL_DIRECTORY% ^
    --fresh

@REM -------------------------------------
@REM Build httpd 
@REM -------------------------------------
cmake --build .

@REM -------------------------------------
@REM Install httpd only 
@REM -------------------------------------
cmake --install . --config %BUILD_TYPE%
POPD

@REM -------------------------------------
@REM Copy the dependencies.
@REM -------------------------------------
if %BUILD_TYPE% == "Debug" (
    SET VCPKG_DIRECTORY_LIB=%VCPKG_DIRECTORY_LIB%\debug
)

@REM -------------------------------------
@REM Copy the libraries needed to run httpd
@REM -------------------------------------
xcopy %VCPKG_DIRECTORY_LIB%\bin\* %HTTPD_INSTALL_DIRECTORY%\bin /y /f /i

@REM -------------------------------------
@REM Run the pyHttpd tests
@REM -------------------------------------
PUSHD test\
@REM python.exe -m pip install --upgrade pip
@REM python.exe -m venv .venv
@REM call .venv\Scripts\activate
@REM call python.exe -m pip install websockets filelock cryptography pyopenssl python-multipart pebble pytest-html pytest==8.4.2 cffi
@REM call python.exe -m pytest -vvv --ignore="modules/http2" -k "not test_cgi_003_01 and not test_800_websockets and not test_02_unix and not test_003_get and not test_004_post and not test_002_restarts and not test_005_trailers" --junitxml="reports/pytest-results.xml" --html="reports/Results" --self-contained-html
@REM deactivate

POPD
