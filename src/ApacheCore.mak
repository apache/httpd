# Microsoft Developer Studio Generated NMAKE File, Based on ApacheCore.dsp
!IF "$(CFG)" == ""
CFG=ApacheCore - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheCore - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheCore - Win32 Release" && "$(CFG)" !=\
 "ApacheCore - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak" CFG="ApacheCore - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheCore - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheCore - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheCore.dll"

!ELSE 

ALL : "Win9xConHook - Win32 Release" "regex - Win32 Release"\
 "gen_uri_delims - Win32 Release" "gen_test_char - Win32 Release"\
 "ApacheOS - Win32 Release" "ap - Win32 Release" "$(OUTDIR)\ApacheCore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ap - Win32 ReleaseCLEAN" "ApacheOS - Win32 ReleaseCLEAN"\
 "gen_test_char - Win32 ReleaseCLEAN" "gen_uri_delims - Win32 ReleaseCLEAN"\
 "regex - Win32 ReleaseCLEAN" "Win9xConHook - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\ApacheCore.idb"
	-@erase "$(INTDIR)\buff.obj"
	-@erase "$(INTDIR)\buildmark.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\http_config.obj"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_log.obj"
	-@erase "$(INTDIR)\http_main.obj"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\http_vhost.obj"
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
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\readdir.obj"
	-@erase "$(INTDIR)\registry.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_uri.obj"
	-@erase "$(INTDIR)\util_win32.obj"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.lib"
	-@erase "$(OUTDIR)\ApacheCore.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I ".\include" /I ".\os\win32" /I\
 ".\os\win32\win9xconhook" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheCore" /FD /c 
CPP_OBJS=.\Release/
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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheCore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib /nologo\
 /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\ApacheCore.pdb"\
 /map:"$(INTDIR)\ApacheCore.map" /machine:I386 /def:".\ApacheCore.def"\
 /out:"$(OUTDIR)\ApacheCore.dll" /implib:"$(OUTDIR)\ApacheCore.lib"\
 /base:@"os\win32\BaseAddr.ref",ApacheCore 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
	"$(INTDIR)\buildmark.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\http_config.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_log.obj" \
	"$(INTDIR)\http_main.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\http_vhost.obj" \
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
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\readdir.obj" \
	"$(INTDIR)\registry.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_uri.obj" \
	"$(INTDIR)\util_win32.obj" \
	".\ap\LibR\ap.lib" \
	".\os\win32\LibR\ApacheOS.lib" \
	".\os\win32\Release\Win9xConHook.lib" \
	".\regex\LibR\regex.lib"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheCore.dll"

!ELSE 

ALL : "Win9xConHook - Win32 Debug" "regex - Win32 Debug"\
 "gen_uri_delims - Win32 Debug" "gen_test_char - Win32 Debug"\
 "ApacheOS - Win32 Debug" "ap - Win32 Debug" "$(OUTDIR)\ApacheCore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ap - Win32 DebugCLEAN" "ApacheOS - Win32 DebugCLEAN"\
 "gen_test_char - Win32 DebugCLEAN" "gen_uri_delims - Win32 DebugCLEAN"\
 "regex - Win32 DebugCLEAN" "Win9xConHook - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\ApacheCore.idb"
	-@erase "$(INTDIR)\buff.obj"
	-@erase "$(INTDIR)\buildmark.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\http_config.obj"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_log.obj"
	-@erase "$(INTDIR)\http_main.obj"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\http_vhost.obj"
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
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\readdir.obj"
	-@erase "$(INTDIR)\registry.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_uri.obj"
	-@erase "$(INTDIR)\util_win32.obj"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.lib"
	-@erase "$(OUTDIR)\ApacheCore.map"
	-@erase "$(OUTDIR)\ApacheCore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I ".\include" /I ".\os\win32" /I\
 ".\os\win32\win9xconhook" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheCore" /FD /c 
CPP_OBJS=.\Debug/
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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheCore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib /nologo\
 /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\ApacheCore.pdb"\
 /map:"$(INTDIR)\ApacheCore.map" /debug /machine:I386 /def:".\ApacheCore.def"\
 /out:"$(OUTDIR)\ApacheCore.dll" /implib:"$(OUTDIR)\ApacheCore.lib"\
 /base:@"os\win32\BaseAddr.ref",ApacheCore 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
	"$(INTDIR)\buildmark.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\http_config.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_log.obj" \
	"$(INTDIR)\http_main.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\http_vhost.obj" \
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
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\readdir.obj" \
	"$(INTDIR)\registry.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_uri.obj" \
	"$(INTDIR)\util_win32.obj" \
	".\ap\LibD\ap.lib" \
	".\os\win32\Debug\Win9xConHook.lib" \
	".\os\win32\LibD\ApacheOS.lib" \
	".\regex\LibD\regex.lib"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheCore - Win32 Release" || "$(CFG)" ==\
 "ApacheCore - Win32 Debug"
SOURCE=.\main\alloc.c
DEP_CPP_ALLOC=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\multithread.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_ALLOC=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\buff.c
DEP_CPP_BUFF_=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_BUFF_=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\buildmark.c
DEP_CPP_BUILD=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_BUILD=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\buildmark.obj" : $(SOURCE) $(DEP_CPP_BUILD) "$(INTDIR)"


SOURCE=.\os\win32\getopt.c

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_config.c
DEP_CPP_HTTP_=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\explain.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_core.c
DEP_CPP_HTTP_C=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_md5.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\fnmatch.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\rfc1413.h"\
	".\include\scoreboard.h"\
	".\include\util_md5.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_C=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_log.c
DEP_CPP_HTTP_L=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_L=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_main.c
DEP_CPP_HTTP_M=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\explain.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\multithread.h"\
	".\include\scoreboard.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\getopt.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	".\os\win32\registry.h"\
	".\os\win32\service.h"\
	
NODEP_CPP_HTTP_M=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	".\main\xmlparse.h"\
	

"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_protocol.c
DEP_CPP_HTTP_P=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\util_date.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_P=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_request.c
DEP_CPP_HTTP_R=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\fnmatch.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\scoreboard.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_R=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_vhost.c
DEP_CPP_HTTP_V=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_HTTP_V=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\http_vhost.obj" : $(SOURCE) $(DEP_CPP_HTTP_V) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_access.c
DEP_CPP_MOD_A=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_A=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_actions.c
DEP_CPP_MOD_AC=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_AC=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_alias.c
DEP_CPP_MOD_AL=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_AL=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_asis.c
DEP_CPP_MOD_AS=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_AS=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_auth.c
DEP_CPP_MOD_AU=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_AU=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_autoindex.c
DEP_CPP_MOD_AUT=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\fnmatch.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_AUT=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_AUT) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_cgi.c
DEP_CPP_MOD_C=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_C=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_dir.c
DEP_CPP_MOD_D=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_D=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_env.c
DEP_CPP_MOD_E=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_E=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_imap.c
DEP_CPP_MOD_I=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_I=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_include.c
DEP_CPP_MOD_IN=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_IN=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	".\modules\standard\config.h"\
	".\modules\standard\modules\perl\mod_perl.h"\
	

"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\mod_isapi.c
DEP_CPP_MOD_IS=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_IS=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_isapi.obj" : $(SOURCE) $(DEP_CPP_MOD_IS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_log_config.c
DEP_CPP_MOD_L=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_L=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_mime.c
DEP_CPP_MOD_M=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_M=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_negotiation.c
DEP_CPP_MOD_N=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_N=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_setenvif.c
DEP_CPP_MOD_S=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_S=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_setenvif.obj" : $(SOURCE) $(DEP_CPP_MOD_S) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_so.c
DEP_CPP_MOD_SO=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_SO=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_so.obj" : $(SOURCE) $(DEP_CPP_MOD_SO) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_userdir.c
DEP_CPP_MOD_U=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MOD_U=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\modules.c
DEP_CPP_MODUL=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_config.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_MODUL=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\modules.obj" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\multithread.c
DEP_CPP_MULTI=\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_mmn.h"\
	".\include\hsregex.h"\
	".\include\multithread.h"\
	".\os\win32\os.h"\
	
NODEP_CPP_MULTI=\
	".\include\ap_config_auto.h"\
	

"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\readdir.c
DEP_CPP_READD=\
	".\os\win32\readdir.h"\
	

"$(INTDIR)\readdir.obj" : $(SOURCE) $(DEP_CPP_READD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\registry.c
DEP_CPP_REGIS=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	".\os\win32\service.h"\
	
NODEP_CPP_REGIS=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\registry.obj" : $(SOURCE) $(DEP_CPP_REGIS) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\rfc1413.c
DEP_CPP_RFC14=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\rfc1413.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_RFC14=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\service.c
DEP_CPP_SERVI=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\httpd.h"\
	".\include\multithread.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	".\os\win32\registry.h"\
	".\os\win32\service.h"\
	".\os\win32\Win9xConHook.h"\
	
NODEP_CPP_SERVI=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util.c
DEP_CPP_UTIL_=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\main\test_char.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_UTIL_=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_date.c
DEP_CPP_UTIL_D=\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_mmn.h"\
	".\include\hsregex.h"\
	".\include\util_date.h"\
	".\os\win32\os.h"\
	
NODEP_CPP_UTIL_D=\
	".\include\ap_config_auto.h"\
	

"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_md5.c
DEP_CPP_UTIL_M=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_md5.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\httpd.h"\
	".\include\util_md5.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_UTIL_M=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_script.c
DEP_CPP_UTIL_S=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_config.h"\
	".\include\http_core.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_protocol.h"\
	".\include\http_request.h"\
	".\include\httpd.h"\
	".\include\util_date.h"\
	".\include\util_script.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_UTIL_S=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_uri.c
DEP_CPP_UTIL_U=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_conf_globals.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\main\uri_delims.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_UTIL_U=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\util_uri.obj" : $(SOURCE) $(DEP_CPP_UTIL_U) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\util_win32.c
DEP_CPP_UTIL_W=\
	".\include\ap.h"\
	".\include\ap_alloc.h"\
	".\include\ap_config.h"\
	".\include\ap_ctype.h"\
	".\include\ap_ebcdic.h"\
	".\include\ap_mmn.h"\
	".\include\buff.h"\
	".\include\hsregex.h"\
	".\include\http_log.h"\
	".\include\httpd.h"\
	".\include\util_uri.h"\
	".\os\win32\os.h"\
	".\os\win32\readdir.h"\
	
NODEP_CPP_UTIL_W=\
	".\include\ap_config_auto.h"\
	".\include\sfio.h"\
	

"$(INTDIR)\util_win32.obj" : $(SOURCE) $(DEP_CPP_UTIL_W) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"ap - Win32 Release" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Release" 
   cd ".."

"ap - Win32 ReleaseCLEAN" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ap.mak" CFG="ap - Win32 Release" RECURSE=1\
 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"ap - Win32 Debug" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Debug" 
   cd ".."

"ap - Win32 DebugCLEAN" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ap.mak" CFG="ap - Win32 Debug" RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"ApacheOS - Win32 Release" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Release" 
   cd "..\.."

"ApacheOS - Win32 ReleaseCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheOS.mak"\
 CFG="ApacheOS - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"ApacheOS - Win32 Debug" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Debug" 
   cd "..\.."

"ApacheOS - Win32 DebugCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Debug"\
 RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"gen_test_char - Win32 Release" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Release" 
   cd ".."

"gen_test_char - Win32 ReleaseCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Release" RECURSE=1 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"gen_test_char - Win32 Debug" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Debug" 
   cd ".."

"gen_test_char - Win32 DebugCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_test_char.mak"\
 CFG="gen_test_char - Win32 Debug" RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"gen_uri_delims - Win32 Release" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Release" 
   cd ".."

"gen_uri_delims - Win32 ReleaseCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Release" RECURSE=1 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"gen_uri_delims - Win32 Debug" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Debug" 
   cd ".."

"gen_uri_delims - Win32 DebugCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\gen_uri_delims.mak"\
 CFG="gen_uri_delims - Win32 Debug" RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"regex - Win32 Release" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Release" 
   cd ".."

"regex - Win32 ReleaseCLEAN" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\regex.mak" CFG="regex - Win32 Release"\
 RECURSE=1 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"regex - Win32 Debug" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Debug" 
   cd ".."

"regex - Win32 DebugCLEAN" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\regex.mak" CFG="regex - Win32 Debug"\
 RECURSE=1 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"Win9xConHook - Win32 Release" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak"\
 CFG="Win9xConHook - Win32 Release" 
   cd "..\.."

"Win9xConHook - Win32 ReleaseCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\Win9xConHook.mak"\
 CFG="Win9xConHook - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"Win9xConHook - Win32 Debug" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak"\
 CFG="Win9xConHook - Win32 Debug" 
   cd "..\.."

"Win9xConHook - Win32 DebugCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\Win9xConHook.mak"\
 CFG="Win9xConHook - Win32 Debug" RECURSE=1 
   cd "..\.."

!ENDIF 


!ENDIF 

