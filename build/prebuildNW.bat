@echo off

if not "%NovellLibC%" == "" goto CheckNDK
set NovellLibC=\novell\ndk\libc
@echo Could not find the NovellLibC environment variable
@echo Setting NovellLibC = %NovellLibC%
@echo ---------------------  

:CheckNDK
if exist %NovellLibC%\include\netware.h goto NDKOK
@echo The path to the NDK "%NovellLibC%" is invalid.
@echo Please set then NovellLibC environment variable to the location of the NDK
@echo ---------------------  
goto Done

:NDKOK
@echo # As part of the pre-build process, the utilities GenChars.NLM
@echo #  (Gen Test Chars) and DFTables.NLM (dftables) must be built, 
@echo #  copied to a NetWare server and run using the following commands:
@echo #
@echo # "sys:\genchars >sys:\test_char.h"
@echo # "sys:\dftables >sys:\chartables.c"
@echo #
@echo #  The files "sys:\test_chars.h" and "sys:\chartables.c" must be 
@echo #  copied to "httpd\os\netware" on the build machine.

@echo Fixing up the APR headers
copy ..\srclib\apr\include\apr.hnw ..\srclib\apr\include\apr.h

@echo Fixing up the APR-Util headers
copy ..\srclib\apr-util\include\apu.hnw ..\srclib\apr-util\include\apu.h
copy ..\srclib\apr-util\include\apr_ldap.hnw ..\srclib\apr-util\include\apr_ldap.h

@echo Fixing up the pcre headers
copy ..\srclib\pcre\config.hw ..\srclib\pcre\config.h
copy ..\srclib\pcre\pcre.hw ..\srclib\pcre\pcre.h

@echo Generating the import lists...
set MWCIncludes=..\include;..\modules\http;..\modules\aaa;..\os\netware;..\server\mpm\netware;..\srclib\apr\include;..\srclib\apr-util\include;+%NovellLibC%
mwccnlm -P nw_export.inc -d NETWARE -d CORE_PRIVATE -EP
awk -f make_nw_export.awk nw_export.i |sort >..\os\netware\httpd.imp

rem cd ..\srclib\apr\build
rem call prebuildnw.bat

:Done
pause
