# Microsoft Developer Studio Project File - Name="ApacheCore" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=ApacheCore - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak" CFG="ApacheCore - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheCore - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "ApacheCore - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LibR"
# PROP BASE Intermediate_Dir "LibR"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LibR"
# PROP Intermediate_Dir "LibR"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I ".\include" /I ".\srclib\apr\include" /I ".\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util" /I ".\srclib\sdbm" /I ".\os\win32" /I ".\server\mpm\winnt" /I ".\srclib\expat-lite" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LibD"
# PROP BASE Intermediate_Dir "LibD"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LibD"
# PROP Intermediate_Dir "LibD"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /ZI /Od /I ".\include" /I ".\srclib\apr\include" /I ".\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /I ".\include" /I ".\srclib\apr\include" /I ".\srclib\apr-util" /I ".\srclib\sdbm" /I ".\os\win32" /I ".\server\mpm\winnt" /I ".\srclib\expat-lite" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "ApacheCore - Win32 Release"
# Name "ApacheCore - Win32 Debug"
# Begin Group "Configuration"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=.\include\ap_config.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_mmn.h
# End Source File
# Begin Source File

SOURCE=.\ApacheCore.def
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\buildmark.c
# End Source File
# Begin Source File

SOURCE=.\include\http_conf_globals.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\modules.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\os.h
# End Source File
# End Group
# Begin Group "Generated Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\srclib\apr-util\apu_private.hw

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# Begin Custom Build
InputPath=.\srclib\apr-util\apu_private.hw

".\srclib\apr-util\apu_private.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\srclib\apr-util\apu_private.hw .\srclib\apr-util\apu_private.h >nul 
	echo Created apr-util apu_private.h from apu_private.hw 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

# Begin Custom Build
InputPath=.\srclib\apr-util\apu_private.hw

".\srclib\apr-util\apu_private.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\srclib\apr-util\apu_private.hw .\srclib\apr-util\apu_private.h >nul 
	echo Created apr-util apu_private.h from apu_private.hw 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\server\gen_test_char.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# Begin Custom Build - Generating test_char.h
InputPath=.\server\gen_test_char.exe

".\server\test_char.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

# Begin Custom Build - Generating test_char.h
InputPath=.\server\gen_test_char.exe

".\server\test_char.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\server\gen_uri_delims.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# Begin Custom Build - Generating uri_delims.h
InputPath=.\server\gen_uri_delims.exe

".\server\uri_delims.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_uri_delims.exe >.\server\uri_delims.h 
	echo Generated uri_delims.h from gen_uri_delims.exe 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

# Begin Custom Build - Generating uri_delims.h
InputPath=.\server\gen_uri_delims.exe

".\server\uri_delims.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_uri_delims.exe >.\server\uri_delims.h 
	echo Generated uri_delims.h from gen_uri_delims.exe 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\server\test_char.h
# End Source File
# Begin Source File

SOURCE=.\server\uri_delims.h
# End Source File
# End Group
# Begin Group "ap_buckets"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\ap\ap_buckets.c
# End Source File
# Begin Source File

SOURCE=.\include\ap_buckets.h
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_eos.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_file.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_flush.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_heap.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_pipe.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_pool.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_refcount.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_simple.c
# End Source File
# Begin Source File

SOURCE=.\ap\ap_buckets_socket.c
# End Source File
# End Group
# Begin Group "ap_general"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\ap\ap_base64.c
# End Source File
# Begin Source File

SOURCE=.\include\ap_base64.h
# End Source File
# Begin Source File

SOURCE=.\ap\ap_hooks.c
# End Source File
# Begin Source File

SOURCE=.\include\ap_hooks.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_ring.h
# End Source File
# Begin Source File

SOURCE=.\ap\ap_sha1.c
# End Source File
# Begin Source File

SOURCE=.\include\ap_sha1.h
# End Source File
# Begin Source File

SOURCE=.\srclib\apr-util\apu_dbm.c
# End Source File
# End Group
# Begin Group "httpd"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\server\http_config.c
# End Source File
# Begin Source File

SOURCE=.\include\http_config.h
# End Source File
# Begin Source File

SOURCE=.\server\http_connection.c
# End Source File
# Begin Source File

SOURCE=.\include\http_connection.h
# End Source File
# Begin Source File

SOURCE=.\server\http_core.c
# End Source File
# Begin Source File

SOURCE=.\include\http_core.h
# End Source File
# Begin Source File

SOURCE=.\server\http_log.c
# End Source File
# Begin Source File

SOURCE=.\include\http_log.h
# End Source File
# Begin Source File

SOURCE=.\include\http_main.h
# End Source File
# Begin Source File

SOURCE=.\server\http_protocol.c
# End Source File
# Begin Source File

SOURCE=.\include\http_protocol.h
# End Source File
# Begin Source File

SOURCE=.\server\http_request.c
# End Source File
# Begin Source File

SOURCE=.\include\http_request.h
# End Source File
# Begin Source File

SOURCE=.\server\http_vhost.c
# End Source File
# Begin Source File

SOURCE=.\include\http_vhost.h
# End Source File
# Begin Source File

SOURCE=.\include\httpd.h
# End Source File
# End Group
# Begin Group "modules"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\modules\aaa\mod_access.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_actions.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_alias.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_asis.c
# End Source File
# Begin Source File

SOURCE=.\modules\aaa\mod_auth.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_autoindex.c
# End Source File
# Begin Source File

SOURCE=.\modules\generators\mod_cgi.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_dir.c
# End Source File
# Begin Source File

SOURCE=.\modules\metadata\mod_env.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_imap.c
# End Source File
# Begin Source File

SOURCE=.\modules\filters\mod_include.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\mod_isapi.c
# End Source File
# Begin Source File

SOURCE=.\modules\loggers\mod_log_config.c
# End Source File
# Begin Source File

SOURCE=.\modules\http\mod_mime.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_negotiation.c
# End Source File
# Begin Source File

SOURCE=.\modules\metadata\mod_setenvif.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_so.c
# End Source File
# Begin Source File

SOURCE=.\modules\mappers\mod_userdir.c
# End Source File
# End Group
# Begin Group "util"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\server\rfc1413.c
# End Source File
# Begin Source File

SOURCE=.\include\rfc1413.h
# End Source File
# Begin Source File

SOURCE=.\server\util.c
# End Source File
# Begin Source File

SOURCE=.\server\util_cfgtree.c
# End Source File
# Begin Source File

SOURCE=.\include\util_cfgtree.h
# End Source File
# Begin Source File

SOURCE=.\include\util_charset.h
# End Source File
# Begin Source File

SOURCE=.\server\util_date.c
# End Source File
# Begin Source File

SOURCE=.\include\util_date.h
# End Source File
# Begin Source File

SOURCE=.\include\util_ebcdic.h
# End Source File
# Begin Source File

SOURCE=.\server\util_filter.c
# End Source File
# Begin Source File

SOURCE=.\include\util_filter.h
# End Source File
# Begin Source File

SOURCE=.\server\util_md5.c
# End Source File
# Begin Source File

SOURCE=.\include\util_md5.h
# End Source File
# Begin Source File

SOURCE=.\server\util_script.c
# End Source File
# Begin Source File

SOURCE=.\include\util_script.h
# End Source File
# Begin Source File

SOURCE=.\server\util_uri.c
# End Source File
# Begin Source File

SOURCE=.\include\util_uri.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\util_win32.c
# End Source File
# Begin Source File

SOURCE=.\server\util_xml.c
# End Source File
# Begin Source File

SOURCE=.\include\util_xml.h
# End Source File
# End Group
# Begin Group "mpm_winnt"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\include\ap_listen.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_mpm.h
# End Source File
# Begin Source File

SOURCE=.\server\listen.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm.h
# End Source File
# Begin Source File

SOURCE=.\include\mpm_common.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_default.h
# End Source File
# Begin Source File

SOURCE=.\include\mpm_status.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_winnt.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\mpm_winnt.h
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\registry.c
# End Source File
# Begin Source File

SOURCE=.\server\mpm\winnt\service.c
# End Source File
# End Group
# End Target
# End Project
