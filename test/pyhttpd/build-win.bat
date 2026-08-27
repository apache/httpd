@ECHO off
@REM


@REM -------------------------------------
@REM Make sure the PATH is limited, but only
@REM if build tools are not already available
@REM -------------------------------------
where cl.exe >nul 2>&1 && where cmake.exe >nul 2>&1 && where nmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    set PATH=C:\Windows\system32;C:\Windows
)

@REM -------------------------------------
@REM check for git otherwise install it
@REM -------------------------------------
where git.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 goto :git_ok

@REM git not in PATH, check if PortableGit exists but PATH is missing it
if EXIST "%USERPROFILE%\PortableGit\bin\git.exe" (
    echo "PortableGit found, adding to PATH..."
    SET "PATH=%USERPROFILE%\PortableGit\bin;%PATH%"
    goto :git_ok
)

@REM PortableGit not installed, download and install it
echo "git.exe not found, installing PortableGit..."
curl -L -o git-portable.exe "https://github.com/git-for-windows/git/releases/download/v2.48.1.windows.1/PortableGit-2.48.1-64-bit.7z.exe"
git-portable.exe -y -o"%USERPROFILE%\PortableGit"
if NOT EXIST "%USERPROFILE%\PortableGit\bin\git.exe" (
    echo "ERROR: PortableGit installation failed."
    exit /b 1
)
SET "PATH=%USERPROFILE%\PortableGit\bin;%PATH%"
echo "PortableGit installed successfully."

:git_ok

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
@REM Check for MS build tools cl.exe cmake etc.
@REM -------------------------------------
where cl.exe >nul 2>&1 && where cmake.exe >nul 2>&1 && where nmake.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo "cl.exe, cmake.exe and nmake.exe already in PATH, skipping vcvars64.bat"
    SET "VCVARS_DONE=1"
    goto :tools_ok
)

SET "VCVARS_DONE=0"
if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    echo "found1: Professional edition"
    SET "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :tools_ok
)
if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    echo "found2: Community edition"
    SET "VCVARS_BAT=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :tools_ok
)
if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    echo "found3: Build Tools edition"
    SET "VCVARS_BAT=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    goto :tools_ok
)

@REM None found - tell the user to install Visual Studio Build Tools
echo "ERROR: No Visual Studio 2022 build tools found."
echo "Please install one of:"
echo "  - Visual Studio 2022 Professional"
echo "  - Visual Studio 2022 Community"
echo "  - Visual Studio 2022 Build Tools"
echo "from https://visualstudio.microsoft.com/downloads/"

@REM -------------------------------------
@REM try to downlaod and install it.
@REM -------------------------------------

curl -L -o vs_buildtools.exe "https://aka.ms/vs/17/release/vs_buildtools.exe"
vs_buildtools.exe --quiet --wait --norestart --nocache ^
    --add Microsoft.VisualStudio.Workload.VCTools ^
    --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
    --add Microsoft.VisualStudio.Component.Windows11SDK.22621 ^
    --includeRecommended

@REM After install, check again for BuildTools vcvars64.bat
if NOT EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    echo "ERROR: Build Tools installation failed or vcvars64.bat not found."
    exit /b 1
)
echo "found3: Build Tools edition (just installed)"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

@REM Verify cl.exe, cmake.exe and nmake.exe are now available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo "ERROR: cl.exe still not found after installing Build Tools."
    exit /b 1
)
where cmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo "ERROR: cmake.exe not found. Please install CMake."
    exit /b 1
)
where nmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo "ERROR: nmake.exe not found after installing Build Tools."
    exit /b 1
)
SET "VCVARS_DONE=1"

:tools_ok
where cmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo "ERROR: cmake.exe not found in PATH. Please install CMake."
    exit /b 1
)
where nmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo "ERROR: nmake.exe not found in PATH."
    exit /b 1
)

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
@REM -------------------------------------
if "%VCVARS_DONE%" == "1" (
    echo "Build environment already configured, skipping vcvars64.bat"
) else (
    call "%VCVARS_BAT%"
)

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
