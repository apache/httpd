@echo off
rem # As part of the pre-build process, the utilities GenChars.NLM
rem #  (Gen Test Chars) and DFTables.NLM (dftables) must be built, 
rem #  copied to a NetWare server and run using the following commands:
rem #
rem # genchars >test_char.h
rem # dftables >chartables.c
rem #
rem #  The files "sys:\test_chars.h" and "sys:\chartables.c" must be 
rem #  copied to "httpd\os\netware" on the build machine.

@echo Fixing up the APR headers
copy ..\srclib\apr\include\apr.hnw ..\srclib\apr\include\apr.h

@echo Fixing up the APR-Util headers
copy ..\srclib\apr-util\include\apu.h.in ..\srclib\apr-util\include\apu.h

@echo Fixing up the pcre headers
copy ..\srclib\pcre\config.hw ..\srclib\pcre\config.h
copy ..\srclib\pcre\pcre.hw ..\srclib\pcre\pcre.h

@echo Generating the import lists...
awk95 -f make_nw_export.awk ..\srclib\apr\include\*.h |sort > ..\srclib\apr\aprlib.imp
awk95 -f make_nw_export.awk ..\srclib\apr-util\include\*.h |sort > ..\srclib\apr\aprutil.imp
awk95 -f make_nw_export.awk ..\include\*.h |sort > ..\os\netware\httpd.imp
