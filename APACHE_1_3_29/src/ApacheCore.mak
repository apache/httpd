# Microsoft Developer Studio Generated NMAKE File, Based on ApacheCore.dsp
!IF "$(CFG)" == ""
CFG=ApacheCore - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheCore - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheCore - Win32 Release" && "$(CFG)" != "ApacheCore - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak" CFG="ApacheCore - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheCore - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheCore - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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

ALL : "Win9xConHook - Win32 Release" "regex - Win32 Release" "gen_uri_delims - Win32 Release" "gen_test_char - Win32 Release" "ApacheOS - Win32 Release" "ap - Win32 Release" "$(OUTDIR)\ApacheCore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ap - Win32 ReleaseCLEAN" "ApacheOS - Win32 ReleaseCLEAN" "gen_test_char - Win32 ReleaseCLEAN" "gen_uri_delims - Win32 ReleaseCLEAN" "regex - Win32 ReleaseCLEAN" "Win9xConHook - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\ApacheCore_src.idb"
	-@erase "$(INTDIR)\ApacheCore_src.pdb"
	-@erase "$(INTDIR)\buff.obj"
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
	-@erase "$(OUTDIR)\ApacheCore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /I ".\include" /I ".\os\win32" /I ".\os\win32\win9xconhook" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheCore_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
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
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib "Release\buildmark.obj" /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\ApacheCore.pdb" /debug /machine:I386 /def:".\ApacheCore.def" /out:"$(OUTDIR)\ApacheCore.dll" /implib:"$(OUTDIR)\ApacheCore.lib" /base:@"os\win32\BaseAddr.ref",ApacheCore /opt:ref 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
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
	".\regex\LibR\regex.lib" \
	".\os\win32\Release\Win9xConHook.lib"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
   cl.exe /nologo /MD /W3 /O2 /Zi /I "./include" /I ".\os\win32" /I ".\os\win32\win9xconhook" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /Fd"Release\ApacheCore_src" /FD /c .\buildmark.c /Fo"Release\buildmark.obj"
	 $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE="$(InputPath)"

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheCore.dll"

!ELSE 

ALL : "Win9xConHook - Win32 Debug" "regex - Win32 Debug" "gen_uri_delims - Win32 Debug" "gen_test_char - Win32 Debug" "ApacheOS - Win32 Debug" "ap - Win32 Debug" "$(OUTDIR)\ApacheCore.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ap - Win32 DebugCLEAN" "ApacheOS - Win32 DebugCLEAN" "gen_test_char - Win32 DebugCLEAN" "gen_uri_delims - Win32 DebugCLEAN" "regex - Win32 DebugCLEAN" "Win9xConHook - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\ApacheCore_src.idb"
	-@erase "$(INTDIR)\ApacheCore_src.pdb"
	-@erase "$(INTDIR)\buff.obj"
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
	-@erase "$(OUTDIR)\ApacheCore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I ".\include" /I ".\os\win32" /I ".\os\win32\win9xconhook" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheCore_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
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
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib "Debug\buildmark.obj" /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\ApacheCore.pdb" /debug /machine:I386 /def:".\ApacheCore.def" /out:"$(OUTDIR)\ApacheCore.dll" /implib:"$(OUTDIR)\ApacheCore.lib" /base:@"os\win32\BaseAddr.ref",ApacheCore 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
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
	".\os\win32\LibD\ApacheOS.lib" \
	".\regex\LibD\regex.lib" \
	".\os\win32\Debug\Win9xConHook.lib"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
   cl.exe /nologo /MDd /W3 /GX /Zi /Od /I ".\include" /I ".\os\win32" /I ".\os\win32\win9xconhook" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /Fd"Debug\ApacheCore_src" /FD /c .\buildmark.c /Fo"Debug\buildmark.obj"
	 $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE="$(InputPath)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("ApacheCore.dep")
!INCLUDE "ApacheCore.dep"
!ELSE 
!MESSAGE Warning: cannot find "ApacheCore.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "ApacheCore - Win32 Release" || "$(CFG)" == "ApacheCore - Win32 Debug"
SOURCE=.\main\alloc.c

"$(INTDIR)\alloc.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\buff.c

"$(INTDIR)\buff.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\getopt.c

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_config.c

"$(INTDIR)\http_config.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_core.c

"$(INTDIR)\http_core.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_log.c

"$(INTDIR)\http_log.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_main.c

"$(INTDIR)\http_main.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_protocol.c

"$(INTDIR)\http_protocol.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_request.c

"$(INTDIR)\http_request.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\http_vhost.c

"$(INTDIR)\http_vhost.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_access.c

"$(INTDIR)\mod_access.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_actions.c

"$(INTDIR)\mod_actions.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_alias.c

"$(INTDIR)\mod_alias.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_asis.c

"$(INTDIR)\mod_asis.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_auth.c

"$(INTDIR)\mod_auth.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_autoindex.c

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_cgi.c

"$(INTDIR)\mod_cgi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_dir.c

"$(INTDIR)\mod_dir.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_env.c

"$(INTDIR)\mod_env.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_imap.c

"$(INTDIR)\mod_imap.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_include.c

"$(INTDIR)\mod_include.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\mod_isapi.c

"$(INTDIR)\mod_isapi.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_log_config.c

"$(INTDIR)\mod_log_config.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_mime.c

"$(INTDIR)\mod_mime.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_negotiation.c

"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_setenvif.c

"$(INTDIR)\mod_setenvif.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_so.c

"$(INTDIR)\mod_so.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\modules\standard\mod_userdir.c

"$(INTDIR)\mod_userdir.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\modules.c

"$(INTDIR)\modules.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\multithread.c

"$(INTDIR)\multithread.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\readdir.c

"$(INTDIR)\readdir.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\registry.c

"$(INTDIR)\registry.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\rfc1413.c

"$(INTDIR)\rfc1413.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\service.c

"$(INTDIR)\service.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util.c

"$(INTDIR)\util.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_date.c

"$(INTDIR)\util_date.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_md5.c

"$(INTDIR)\util_md5.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_script.c

"$(INTDIR)\util_script.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\main\util_uri.c

"$(INTDIR)\util_uri.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\os\win32\util_win32.c

"$(INTDIR)\util_win32.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"ap - Win32 Release" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Release" 
   cd ".."

"ap - Win32 ReleaseCLEAN" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Release" RECURSE=1 CLEAN 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"ap - Win32 Debug" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Debug" 
   cd ".."

"ap - Win32 DebugCLEAN" : 
   cd ".\ap"
   $(MAKE) /$(MAKEFLAGS) /F ".\ap.mak" CFG="ap - Win32 Debug" RECURSE=1 CLEAN 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"ApacheOS - Win32 Release" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Release" 
   cd "..\.."

"ApacheOS - Win32 ReleaseCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Release" RECURSE=1 CLEAN 
   cd "..\.."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"ApacheOS - Win32 Debug" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Debug" 
   cd "..\.."

"ApacheOS - Win32 DebugCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheOS.mak" CFG="ApacheOS - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"gen_test_char - Win32 Release" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak" CFG="gen_test_char - Win32 Release" 
   cd ".."

"gen_test_char - Win32 ReleaseCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak" CFG="gen_test_char - Win32 Release" RECURSE=1 CLEAN 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"gen_test_char - Win32 Debug" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak" CFG="gen_test_char - Win32 Debug" 
   cd ".."

"gen_test_char - Win32 DebugCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_test_char.mak" CFG="gen_test_char - Win32 Debug" RECURSE=1 CLEAN 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"gen_uri_delims - Win32 Release" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Release" 
   cd ".."

"gen_uri_delims - Win32 ReleaseCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Release" RECURSE=1 CLEAN 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"gen_uri_delims - Win32 Debug" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Debug" 
   cd ".."

"gen_uri_delims - Win32 DebugCLEAN" : 
   cd ".\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Debug" RECURSE=1 CLEAN 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"regex - Win32 Release" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Release" 
   cd ".."

"regex - Win32 ReleaseCLEAN" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Release" RECURSE=1 CLEAN 
   cd ".."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"regex - Win32 Debug" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Debug" 
   cd ".."

"regex - Win32 DebugCLEAN" : 
   cd ".\regex"
   $(MAKE) /$(MAKEFLAGS) /F ".\regex.mak" CFG="regex - Win32 Debug" RECURSE=1 CLEAN 
   cd ".."

!ENDIF 

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

"Win9xConHook - Win32 Release" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak" CFG="Win9xConHook - Win32 Release" 
   cd "..\.."

"Win9xConHook - Win32 ReleaseCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak" CFG="Win9xConHook - Win32 Release" RECURSE=1 CLEAN 
   cd "..\.."

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

"Win9xConHook - Win32 Debug" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak" CFG="Win9xConHook - Win32 Debug" 
   cd "..\.."

"Win9xConHook - Win32 DebugCLEAN" : 
   cd ".\os\win32"
   $(MAKE) /$(MAKEFLAGS) /F ".\Win9xConHook.mak" CFG="Win9xConHook - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\.."

!ENDIF 


!ENDIF 

