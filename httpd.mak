# Microsoft Developer Studio Generated NMAKE File, Based on httpd.dsp
!IF "$(CFG)" == ""
CFG=httpd - Win32 Debug
!MESSAGE No configuration specified. Defaulting to httpd - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "httpd - Win32 Release" && "$(CFG)" != "httpd - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "httpd.mak" CFG="httpd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "httpd - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "httpd - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "httpd - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\httpd.lib"

!ELSE 

ALL : "libaprutil - Win32 Release" "libapr - Win32 Release"\
 "gen_uri_delims - Win32 Release" "gen_test_char - Win32 Release"\
 "$(OUTDIR)\httpd.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"gen_test_char - Win32 ReleaseCLEAN"\
 "gen_uri_delims - Win32 ReleaseCLEAN" "libapr - Win32 ReleaseCLEAN"\
 "libaprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\buildmark.obj"
	-@erase "$(INTDIR)\config.obj"
	-@erase "$(INTDIR)\connection.obj"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\httpd.idb"
	-@erase "$(INTDIR)\listen.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\mod_access.obj"
	-@erase "$(INTDIR)\mod_actions.obj"
	-@erase "$(INTDIR)\mod_alias.obj"
	-@erase "$(INTDIR)\mod_asis.obj"
	-@erase "$(INTDIR)\mod_auth.obj"
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_env.obj"
	-@erase "$(INTDIR)\mod_imap.obj"
	-@erase "$(INTDIR)\mod_include.obj"
	-@erase "$(INTDIR)\mod_isapi.obj"
	-@erase "$(INTDIR)\mod_log_config.obj"
	-@erase "$(INTDIR)\mod_mime.obj"
	-@erase "$(INTDIR)\mod_negotiation.obj"
	-@erase "$(INTDIR)\mod_setenvif.obj"
	-@erase "$(INTDIR)\mod_so.obj"
	-@erase "$(INTDIR)\mod_userdir.obj"
	-@erase "$(INTDIR)\modules.obj"
	-@erase "$(INTDIR)\mpm_winnt.obj"
	-@erase "$(INTDIR)\registry.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_cfgtree.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_filter.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_uri.obj"
	-@erase "$(INTDIR)\util_win32.obj"
	-@erase "$(INTDIR)\util_xml.obj"
	-@erase "$(INTDIR)\vhost.obj"
	-@erase "$(OUTDIR)\httpd.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I ".\include" /I ".\srclib\apr\include" /I\
 ".\srclib\apr-util\include" /I ".\srclib\sdbm" /I ".\os\win32" /I\
 ".\server\mpm\winnt" /I ".\srclib\expat-lite" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "AP_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\httpd" /FD /c 
CPP_OBJS=.\LibR/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\httpd.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\httpd.lib" 
LIB32_OBJS= \
	"$(INTDIR)\buildmark.obj" \
	"$(INTDIR)\config.obj" \
	"$(INTDIR)\connection.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\listen.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mod_access.obj" \
	"$(INTDIR)\mod_actions.obj" \
	"$(INTDIR)\mod_alias.obj" \
	"$(INTDIR)\mod_asis.obj" \
	"$(INTDIR)\mod_auth.obj" \
	"$(INTDIR)\mod_autoindex.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_isapi.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_setenvif.obj" \
	"$(INTDIR)\mod_so.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\mpm_winnt.obj" \
	"$(INTDIR)\registry.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_cfgtree.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_filter.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_uri.obj" \
	"$(INTDIR)\util_win32.obj" \
	"$(INTDIR)\util_xml.obj" \
	"$(INTDIR)\vhost.obj" \
	".\srclib\apr-util\Release\libaprutil.lib" \
	".\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\httpd.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\httpd.lib"

!ELSE 

ALL : "libaprutil - Win32 Debug" "libapr - Win32 Debug"\
 "gen_uri_delims - Win32 Debug" "gen_test_char - Win32 Debug"\
 "$(OUTDIR)\httpd.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"gen_test_char - Win32 DebugCLEAN" "gen_uri_delims - Win32 DebugCLEAN"\
 "libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\buildmark.obj"
	-@erase "$(INTDIR)\config.obj"
	-@erase "$(INTDIR)\connection.obj"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\httpd.idb"
	-@erase "$(INTDIR)\httpd.pdb"
	-@erase "$(INTDIR)\listen.obj"
	-@erase "$(INTDIR)\log.obj"
	-@erase "$(INTDIR)\mod_access.obj"
	-@erase "$(INTDIR)\mod_actions.obj"
	-@erase "$(INTDIR)\mod_alias.obj"
	-@erase "$(INTDIR)\mod_asis.obj"
	-@erase "$(INTDIR)\mod_auth.obj"
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_env.obj"
	-@erase "$(INTDIR)\mod_imap.obj"
	-@erase "$(INTDIR)\mod_include.obj"
	-@erase "$(INTDIR)\mod_isapi.obj"
	-@erase "$(INTDIR)\mod_log_config.obj"
	-@erase "$(INTDIR)\mod_mime.obj"
	-@erase "$(INTDIR)\mod_negotiation.obj"
	-@erase "$(INTDIR)\mod_setenvif.obj"
	-@erase "$(INTDIR)\mod_so.obj"
	-@erase "$(INTDIR)\mod_userdir.obj"
	-@erase "$(INTDIR)\modules.obj"
	-@erase "$(INTDIR)\mpm_winnt.obj"
	-@erase "$(INTDIR)\registry.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_cfgtree.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_filter.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_uri.obj"
	-@erase "$(INTDIR)\util_win32.obj"
	-@erase "$(INTDIR)\util_xml.obj"
	-@erase "$(INTDIR)\vhost.obj"
	-@erase "$(OUTDIR)\httpd.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I ".\include" /I ".\srclib\apr\include"\
 /I ".\srclib\apr-util\include" /I ".\srclib\sdbm" /I ".\os\win32" /I\
 ".\server\mpm\winnt" /I ".\srclib\expat-lite" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "AP_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\httpd" /FD /c 
CPP_OBJS=.\LibD/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\httpd.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\httpd.lib" 
LIB32_OBJS= \
	"$(INTDIR)\buildmark.obj" \
	"$(INTDIR)\config.obj" \
	"$(INTDIR)\connection.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\listen.obj" \
	"$(INTDIR)\log.obj" \
	"$(INTDIR)\mod_access.obj" \
	"$(INTDIR)\mod_actions.obj" \
	"$(INTDIR)\mod_alias.obj" \
	"$(INTDIR)\mod_asis.obj" \
	"$(INTDIR)\mod_auth.obj" \
	"$(INTDIR)\mod_autoindex.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_isapi.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_setenvif.obj" \
	"$(INTDIR)\mod_so.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\mpm_winnt.obj" \
	"$(INTDIR)\registry.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_cfgtree.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_filter.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_uri.obj" \
	"$(INTDIR)\util_win32.obj" \
	"$(INTDIR)\util_xml.obj" \
	"$(INTDIR)\vhost.obj" \
	".\srclib\apr-util\Debug\libaprutil.lib" \
	".\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\httpd.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "httpd - Win32 Release" || "$(CFG)" == "httpd - Win32 Debug"
SOURCE=.\server\buildmark.c
DEP_CPP_BUILD=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_BUILD=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\buildmark.obj" : $(SOURCE) $(DEP_CPP_BUILD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\modules.c
DEP_CPP_MODUL=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MODUL=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\modules.obj" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\gen_test_char.exe

!IF  "$(CFG)" == "httpd - Win32 Release"

InputPath=.\server\gen_test_char.exe

".\server\test_char.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

InputPath=.\server\gen_test_char.exe

".\server\test_char.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_test_char.exe >.\server\test_char.h 
	echo Generated test_char.h from gen_test_char.exe 
	

!ENDIF 

SOURCE=.\server\gen_uri_delims.exe

!IF  "$(CFG)" == "httpd - Win32 Release"

InputPath=.\server\gen_uri_delims.exe

".\server\uri_delims.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_uri_delims.exe >.\server\uri_delims.h 
	echo Generated uri_delims.h from gen_uri_delims.exe 
	

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

InputPath=.\server\gen_uri_delims.exe

".\server\uri_delims.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\server\gen_uri_delims.exe >.\server\uri_delims.h 
	echo Generated uri_delims.h from gen_uri_delims.exe 
	

!ENDIF 

SOURCE=.\server\config.c
DEP_CPP_CONFI=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_CONFI=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\config.obj" : $(SOURCE) $(DEP_CPP_CONFI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\connection.c
DEP_CPP_CONNE=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\ap_mpm.h"\
	".\include\http_config.h"\
	".\include\http_connection.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\mpm_status.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_CONNE=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\connection.obj" : $(SOURCE) $(DEP_CPP_CONNE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\log.c
DEP_CPP_LOG_C=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_LOG_C=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\log.obj" : $(SOURCE) $(DEP_CPP_LOG_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\vhost.c
DEP_CPP_VHOST=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_VHOST=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\vhost.obj" : $(SOURCE) $(DEP_CPP_VHOST) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\http\http_core.c
DEP_CPP_HTTP_=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_connection.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\rfc1413.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\include\util_filter.h"\
	".\include\util_md5.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\mpm\winnt\mpm.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_fnmatch.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_md5.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_HTTP_=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\http\http_protocol.c
DEP_CPP_HTTP_P=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\mpm_status.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_date.h"\
	".\include\util_ebcdic.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_HTTP_P=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\http\http_request.c
DEP_CPP_HTTP_R=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_fnmatch.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_HTTP_R=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\aaa\mod_access.c
DEP_CPP_MOD_A=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_A=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_actions.c
DEP_CPP_MOD_AC=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_AC=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_alias.c
DEP_CPP_MOD_AL=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_AL=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\generators\mod_asis.c
DEP_CPP_MOD_AS=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_AS=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\aaa\mod_auth.c
DEP_CPP_MOD_AU=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_md5.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_AU=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\generators\mod_autoindex.c
DEP_CPP_MOD_AUT=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_fnmatch.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_AUT=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_AUT) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\generators\mod_cgi.c
DEP_CPP_MOD_C=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\ap_mpm.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_C=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_dir.c
DEP_CPP_MOD_D=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_D=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\metadata\mod_env.c
DEP_CPP_MOD_E=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_E=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_imap.c
DEP_CPP_MOD_I=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_I=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\filters\mod_include.c
DEP_CPP_MOD_IN=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\modules\filters\mod_include.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_hash.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_IN=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\mod_isapi.c
DEP_CPP_MOD_IS=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_IS=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_isapi.obj" : $(SOURCE) $(DEP_CPP_MOD_IS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\loggers\mod_log_config.c
DEP_CPP_MOD_L=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_L=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\http\mod_mime.c
DEP_CPP_MOD_M=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_M=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_negotiation.c
DEP_CPP_MOD_N=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_N=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\metadata\mod_setenvif.c
DEP_CPP_MOD_S=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_S=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_setenvif.obj" : $(SOURCE) $(DEP_CPP_MOD_S) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_so.c
DEP_CPP_MOD_SO=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_SO=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mod_so.obj" : $(SOURCE) $(DEP_CPP_MOD_SO) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\mappers\mod_userdir.c
DEP_CPP_MOD_U=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_user.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MOD_U=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	".\modules\mappers\unixd.h"\
	

"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\rfc1413.c
DEP_CPP_RFC14=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\rfc1413.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_RFC14=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util.c
DEP_CPP_UTIL_=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\test_char.h"\
	".\srclib\apr-util\include\ap_base64.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"\
 ".\server\test_char.h"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_cfgtree.c
DEP_CPP_UTIL_C=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\util_cfgtree.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_C=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_cfgtree.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_date.c
DEP_CPP_UTIL_D=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\util_date.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_D=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_filter.c
DEP_CPP_UTIL_F=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_F=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_filter.obj" : $(SOURCE) $(DEP_CPP_UTIL_F) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_md5.c
DEP_CPP_UTIL_M=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\include\util_md5.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_md5.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_M=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_script.c
DEP_CPP_UTIL_S=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_date.h"\
	".\include\util_ebcdic.h"\
	".\include\util_filter.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_xlate.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_S=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_uri.c
DEP_CPP_UTIL_U=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\uri_delims.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_U=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_uri.obj" : $(SOURCE) $(DEP_CPP_UTIL_U) "$(INTDIR)"\
 ".\server\uri_delims.h"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\util_win32.c
DEP_CPP_UTIL_W=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_UTIL_W=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_win32.obj" : $(SOURCE) $(DEP_CPP_UTIL_W) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\util_xml.c
DEP_CPP_UTIL_X=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_filter.h"\
	".\include\util_uri.h"\
	".\include\util_xml.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\ap_buckets.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr-util\include\ap_ring.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_mmap.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	".\srclib\expat-lite\xmlparse.h"\
	
NODEP_CPP_UTIL_X=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\util_xml.obj" : $(SOURCE) $(DEP_CPP_UTIL_X) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\listen.c
DEP_CPP_LISTE=\
	".\include\ap_config.h"\
	".\include\ap_listen.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\mpm_common.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\mpm\winnt\mpm.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_LISTE=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\listen.obj" : $(SOURCE) $(DEP_CPP_LISTE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\mpm\winnt\mpm_winnt.c
DEP_CPP_MPM_W=\
	".\include\ap_config.h"\
	".\include\ap_listen.h"\
	".\include\ap_mmn.h"\
	".\include\ap_mpm.h"\
	".\include\http_config.h"\
	".\include\http_connection.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\mpm_common.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\mpm\winnt\mpm.h"\
	".\server\mpm\winnt\mpm_default.h"\
	".\server\mpm\winnt\mpm_winnt.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_dso.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_getopt.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_lock.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_portable.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_MPM_W=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\mpm_winnt.obj" : $(SOURCE) $(DEP_CPP_MPM_W) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\mpm\winnt\registry.c
DEP_CPP_REGIS=\
	".\include\ap_config.h"\
	".\include\ap_listen.h"\
	".\include\ap_mmn.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\mpm\winnt\mpm.h"\
	".\server\mpm\winnt\mpm_winnt.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_REGIS=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\registry.obj" : $(SOURCE) $(DEP_CPP_REGIS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\server\mpm\winnt\service.c
DEP_CPP_SERVI=\
	".\include\ap_config.h"\
	".\include\ap_listen.h"\
	".\include\ap_mmn.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\server\mpm\winnt\mpm.h"\
	".\server\mpm\winnt\mpm_winnt.h"\
	".\srclib\apr-util\include\ap_hooks.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\network_io\os2\os2nerrno.h"\
	
NODEP_CPP_SERVI=\
	".\include\ap_config_auto.h"\
	".\include\ap_config_path.h"\
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "httpd - Win32 Release"

"gen_test_char - Win32 Release" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Release" 
   cd ".."

"gen_test_char - Win32 ReleaseCLEAN" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Release" RECURSE=1 
   cd ".."

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

"gen_test_char - Win32 Debug" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Debug" 
   cd ".."

"gen_test_char - Win32 DebugCLEAN" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Debug" RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "httpd - Win32 Release"

"gen_uri_delims - Win32 Release" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Release" 
   cd ".."

"gen_uri_delims - Win32 ReleaseCLEAN" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Release" RECURSE=1 
   cd ".."

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

"gen_uri_delims - Win32 Debug" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Debug" 
   cd ".."

"gen_uri_delims - Win32 DebugCLEAN" : 
   cd ".\server"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Debug" RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "httpd - Win32 Release"

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

!ENDIF 

!IF  "$(CFG)" == "httpd - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\.."

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\.."

"libapr - Win32 DebugCLEAN" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "httpd - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\.."

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\.."

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\.."

!ENDIF 


!ENDIF 

