@echo off
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

@echo Fixing up the pcre headers
copy ..\srclib\pcre\config.hw ..\srclib\pcre\config.h
copy ..\srclib\pcre\pcre.hw ..\srclib\pcre\pcre.h

@echo Generating the import lists...
awk -f ..\srclib\apr\build\make_nw_export.awk ..\srclib\apr\include\*.h |sort > ..\srclib\apr\aprlib.imp
awk -f ..\srclib\apr\build\make_nw_export.awk ..\srclib\apr-util\include\*.h |sort >> ..\srclib\apr\aprlib.imp
awk -f make_nw_export.awk ..\include\*.h ..\modules\http\*.h |sort > ..\os\netware\httpd.imp
