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

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

OUTDIR=.\CoreR
INTDIR=.\CoreR
# Begin Custom Macros
OutDir=.\.\CoreR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheCore.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheCore.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\buff.obj"
	-@erase "$(INTDIR)\explain.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\http_bprintf.obj"
	-@erase "$(INTDIR)\http_config.obj"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_log.obj"
	-@erase "$(INTDIR)\http_main.obj"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\md5c.obj"
	-@erase "$(INTDIR)\mod_access.obj"
	-@erase "$(INTDIR)\mod_actions.obj"
	-@erase "$(INTDIR)\mod_alias.obj"
	-@erase "$(INTDIR)\mod_asis.obj"
	-@erase "$(INTDIR)\mod_auth.obj"
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_dll.obj"
	-@erase "$(INTDIR)\mod_env.obj"
	-@erase "$(INTDIR)\mod_imap.obj"
	-@erase "$(INTDIR)\mod_include.obj"
	-@erase "$(INTDIR)\mod_log_config.obj"
	-@erase "$(INTDIR)\mod_mime.obj"
	-@erase "$(INTDIR)\mod_negotiation.obj"
	-@erase "$(INTDIR)\mod_userdir.obj"
	-@erase "$(INTDIR)\modules.obj"
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\readdir.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_snprintf.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I ".\regex" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)\ApacheCore.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\CoreR/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheCore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheCore.pdb" /machine:I386 /def:".\ApacheCore.def"\
 /out:"$(OUTDIR)\ApacheCore.dll" /implib:"$(OUTDIR)\ApacheCore.lib" 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
	"$(INTDIR)\explain.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\http_bprintf.obj" \
	"$(INTDIR)\http_config.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_log.obj" \
	"$(INTDIR)\http_main.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\md5c.obj" \
	"$(INTDIR)\mod_access.obj" \
	"$(INTDIR)\mod_actions.obj" \
	"$(INTDIR)\mod_alias.obj" \
	"$(INTDIR)\mod_asis.obj" \
	"$(INTDIR)\mod_auth.obj" \
	"$(INTDIR)\mod_autoindex.obj" \
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_dll.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\readdir.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

OUTDIR=.\CoreD
INTDIR=.\CoreD
# Begin Custom Macros
OutDir=.\.\CoreD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheCore.dll" "$(OUTDIR)\ApacheCore.bsc"

!ELSE 

ALL : "$(OUTDIR)\ApacheCore.dll" "$(OUTDIR)\ApacheCore.bsc"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\alloc.obj"
	-@erase "$(INTDIR)\alloc.sbr"
	-@erase "$(INTDIR)\buff.obj"
	-@erase "$(INTDIR)\buff.sbr"
	-@erase "$(INTDIR)\explain.obj"
	-@erase "$(INTDIR)\explain.sbr"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\getopt.sbr"
	-@erase "$(INTDIR)\http_bprintf.obj"
	-@erase "$(INTDIR)\http_bprintf.sbr"
	-@erase "$(INTDIR)\http_config.obj"
	-@erase "$(INTDIR)\http_config.sbr"
	-@erase "$(INTDIR)\http_core.obj"
	-@erase "$(INTDIR)\http_core.sbr"
	-@erase "$(INTDIR)\http_log.obj"
	-@erase "$(INTDIR)\http_log.sbr"
	-@erase "$(INTDIR)\http_main.obj"
	-@erase "$(INTDIR)\http_main.sbr"
	-@erase "$(INTDIR)\http_protocol.obj"
	-@erase "$(INTDIR)\http_protocol.sbr"
	-@erase "$(INTDIR)\http_request.obj"
	-@erase "$(INTDIR)\http_request.sbr"
	-@erase "$(INTDIR)\md5c.obj"
	-@erase "$(INTDIR)\md5c.sbr"
	-@erase "$(INTDIR)\mod_access.obj"
	-@erase "$(INTDIR)\mod_access.sbr"
	-@erase "$(INTDIR)\mod_actions.obj"
	-@erase "$(INTDIR)\mod_actions.sbr"
	-@erase "$(INTDIR)\mod_alias.obj"
	-@erase "$(INTDIR)\mod_alias.sbr"
	-@erase "$(INTDIR)\mod_asis.obj"
	-@erase "$(INTDIR)\mod_asis.sbr"
	-@erase "$(INTDIR)\mod_auth.obj"
	-@erase "$(INTDIR)\mod_auth.sbr"
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(INTDIR)\mod_autoindex.sbr"
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_browser.sbr"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_cgi.sbr"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_dir.sbr"
	-@erase "$(INTDIR)\mod_dll.obj"
	-@erase "$(INTDIR)\mod_dll.sbr"
	-@erase "$(INTDIR)\mod_env.obj"
	-@erase "$(INTDIR)\mod_env.sbr"
	-@erase "$(INTDIR)\mod_imap.obj"
	-@erase "$(INTDIR)\mod_imap.sbr"
	-@erase "$(INTDIR)\mod_include.obj"
	-@erase "$(INTDIR)\mod_include.sbr"
	-@erase "$(INTDIR)\mod_log_config.obj"
	-@erase "$(INTDIR)\mod_log_config.sbr"
	-@erase "$(INTDIR)\mod_mime.obj"
	-@erase "$(INTDIR)\mod_mime.sbr"
	-@erase "$(INTDIR)\mod_negotiation.obj"
	-@erase "$(INTDIR)\mod_negotiation.sbr"
	-@erase "$(INTDIR)\mod_userdir.obj"
	-@erase "$(INTDIR)\mod_userdir.sbr"
	-@erase "$(INTDIR)\modules.obj"
	-@erase "$(INTDIR)\modules.sbr"
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\multithread.sbr"
	-@erase "$(INTDIR)\readdir.obj"
	-@erase "$(INTDIR)\readdir.sbr"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\rfc1413.sbr"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\service.sbr"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util.sbr"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_date.sbr"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_md5.sbr"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_script.sbr"
	-@erase "$(INTDIR)\util_snprintf.obj"
	-@erase "$(INTDIR)\util_snprintf.sbr"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheCore.bsc"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.ilk"
	-@erase "$(OUTDIR)\ApacheCore.lib"
	-@erase "$(OUTDIR)\ApacheCore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I ".\regex" /D "WIN32" /D "_DEBUG"\
 /D "_WINDOWS" /FR"$(INTDIR)\\" /Fp"$(INTDIR)\ApacheCore.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\CoreD/
CPP_SBRS=.\CoreD/
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheCore.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\alloc.sbr" \
	"$(INTDIR)\buff.sbr" \
	"$(INTDIR)\explain.sbr" \
	"$(INTDIR)\getopt.sbr" \
	"$(INTDIR)\http_bprintf.sbr" \
	"$(INTDIR)\http_config.sbr" \
	"$(INTDIR)\http_core.sbr" \
	"$(INTDIR)\http_log.sbr" \
	"$(INTDIR)\http_main.sbr" \
	"$(INTDIR)\http_protocol.sbr" \
	"$(INTDIR)\http_request.sbr" \
	"$(INTDIR)\md5c.sbr" \
	"$(INTDIR)\mod_access.sbr" \
	"$(INTDIR)\mod_actions.sbr" \
	"$(INTDIR)\mod_alias.sbr" \
	"$(INTDIR)\mod_asis.sbr" \
	"$(INTDIR)\mod_auth.sbr" \
	"$(INTDIR)\mod_autoindex.sbr" \
	"$(INTDIR)\mod_browser.sbr" \
	"$(INTDIR)\mod_cgi.sbr" \
	"$(INTDIR)\mod_dir.sbr" \
	"$(INTDIR)\mod_dll.sbr" \
	"$(INTDIR)\mod_env.sbr" \
	"$(INTDIR)\mod_imap.sbr" \
	"$(INTDIR)\mod_include.sbr" \
	"$(INTDIR)\mod_log_config.sbr" \
	"$(INTDIR)\mod_mime.sbr" \
	"$(INTDIR)\mod_negotiation.sbr" \
	"$(INTDIR)\mod_userdir.sbr" \
	"$(INTDIR)\modules.sbr" \
	"$(INTDIR)\multithread.sbr" \
	"$(INTDIR)\readdir.sbr" \
	"$(INTDIR)\rfc1413.sbr" \
	"$(INTDIR)\service.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\util_date.sbr" \
	"$(INTDIR)\util_md5.sbr" \
	"$(INTDIR)\util_script.sbr" \
	"$(INTDIR)\util_snprintf.sbr"

"$(OUTDIR)\ApacheCore.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
LINK32_FLAGS=regex\debug\regex.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)\ApacheCore.pdb" /debug /machine:I386\
 /def:".\ApacheCore.def" /out:"$(OUTDIR)\ApacheCore.dll"\
 /implib:"$(OUTDIR)\ApacheCore.lib" 
DEF_FILE= \
	".\ApacheCore.def"
LINK32_OBJS= \
	"$(INTDIR)\alloc.obj" \
	"$(INTDIR)\buff.obj" \
	"$(INTDIR)\explain.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\http_bprintf.obj" \
	"$(INTDIR)\http_config.obj" \
	"$(INTDIR)\http_core.obj" \
	"$(INTDIR)\http_log.obj" \
	"$(INTDIR)\http_main.obj" \
	"$(INTDIR)\http_protocol.obj" \
	"$(INTDIR)\http_request.obj" \
	"$(INTDIR)\md5c.obj" \
	"$(INTDIR)\mod_access.obj" \
	"$(INTDIR)\mod_actions.obj" \
	"$(INTDIR)\mod_alias.obj" \
	"$(INTDIR)\mod_asis.obj" \
	"$(INTDIR)\mod_auth.obj" \
	"$(INTDIR)\mod_autoindex.obj" \
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_dll.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\readdir.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\ApacheCore.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

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


!IF "$(CFG)" == "ApacheCore - Win32 Release" || "$(CFG)" ==\
 "ApacheCore - Win32 Debug"
SOURCE=.\alloc.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_ALLOC=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\multithread.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_ALLOC=\
	".\sfio.h"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_ALLOC=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\multithread.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\alloc.obj"	"$(INTDIR)\alloc.sbr" : $(SOURCE) $(DEP_CPP_ALLOC)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\buff.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_BUFF_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_BUFF_=\
	".\sfio.h"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_BUFF_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\buff.obj"	"$(INTDIR)\buff.sbr" : $(SOURCE) $(DEP_CPP_BUFF_)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\explain.c
DEP_CPP_EXPLA=\
	".\explain.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\explain.obj"	"$(INTDIR)\explain.sbr" : $(SOURCE) $(DEP_CPP_EXPLA)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\nt\getopt.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\getopt.obj"	"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\http_bprintf.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_=\
	".\sfio.h"\
	

"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\http_bprintf.obj"	"$(INTDIR)\http_bprintf.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_) "$(INTDIR)"


!ENDIF 

SOURCE=.\http_config.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_C=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\explain.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_C=\
	".\sfio.h"\
	

"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_C=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\explain.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\http_config.obj"	"$(INTDIR)\http_config.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ENDIF 

SOURCE=.\http_core.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_CO=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\md5.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\rfc1413.h"\
	".\scoreboard.h"\
	".\util_md5.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_CO=\
	".\sfio.h"\
	

"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_CO=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\md5.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\rfc1413.h"\
	".\scoreboard.h"\
	".\util_md5.h"\
	

"$(INTDIR)\http_core.obj"	"$(INTDIR)\http_core.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ENDIF 

SOURCE=.\http_log.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_L=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_L=\
	".\sfio.h"\
	

"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_L=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\http_log.obj"	"$(INTDIR)\http_log.sbr" : $(SOURCE) $(DEP_CPP_HTTP_L)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\http_main.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\explain.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\multithread.h"\
	".\nt\getopt.h"\
	".\nt\readdir.h"\
	".\nt\service.h"\
	".\regex\regex.h"\
	".\scoreboard.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_M=\
	".\sfio.h"\
	

"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\explain.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\multithread.h"\
	".\nt\getopt.h"\
	".\nt\readdir.h"\
	".\nt\service.h"\
	".\regex\regex.h"\
	".\scoreboard.h"\
	

"$(INTDIR)\http_main.obj"	"$(INTDIR)\http_main.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ENDIF 

SOURCE=.\http_protocol.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_P=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_date.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_P=\
	".\sfio.h"\
	

"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_P=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_date.h"\
	

"$(INTDIR)\http_protocol.obj"	"$(INTDIR)\http_protocol.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ENDIF 

SOURCE=.\http_request.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_HTTP_R=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\scoreboard.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTTP_R=\
	".\sfio.h"\
	

"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_HTTP_R=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\scoreboard.h"\
	

"$(INTDIR)\http_request.obj"	"$(INTDIR)\http_request.sbr" : $(SOURCE)\
 $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ENDIF 

SOURCE=.\md5c.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MD5C_=\
	".\conf.h"\
	".\md5.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MD5C_=\
	".\conf.h"\
	".\md5.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\md5c.obj"	"$(INTDIR)\md5c.sbr" : $(SOURCE) $(DEP_CPP_MD5C_)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_access.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_A=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_A=\
	".\sfio.h"\
	

"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_A=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_access.obj"	"$(INTDIR)\mod_access.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_A) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_actions.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_AC=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_AC=\
	".\sfio.h"\
	

"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_AC=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_actions.obj"	"$(INTDIR)\mod_actions.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_alias.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_AL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_AL=\
	".\sfio.h"\
	

"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_AL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_alias.obj"	"$(INTDIR)\mod_alias.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_asis.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_AS=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_AS=\
	".\sfio.h"\
	

"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_AS=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_asis.obj"	"$(INTDIR)\mod_asis.sbr" : $(SOURCE) $(DEP_CPP_MOD_AS)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_auth.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_AU=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_AU=\
	".\sfio.h"\
	

"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_AU=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_auth.obj"	"$(INTDIR)\mod_auth.sbr" : $(SOURCE) $(DEP_CPP_MOD_AU)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_autoindex.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_AUT=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_AUT=\
	".\sfio.h"\
	

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_AUT) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_AUT=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_autoindex.obj"	"$(INTDIR)\mod_autoindex.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_AUT) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_browser.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_B=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_B=\
	".\sfio.h"\
	

"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_B=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_browser.obj"	"$(INTDIR)\mod_browser.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_B) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_cgi.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_C=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_C=\
	".\sfio.h"\
	

"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_C=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_cgi.obj"	"$(INTDIR)\mod_cgi.sbr" : $(SOURCE) $(DEP_CPP_MOD_C)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_dir.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_D=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_D=\
	".\sfio.h"\
	

"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_D=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_dir.obj"	"$(INTDIR)\mod_dir.sbr" : $(SOURCE) $(DEP_CPP_MOD_D)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\nt\mod_dll.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_DL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_DL=\
	".\sfio.h"\
	

"$(INTDIR)\mod_dll.obj" : $(SOURCE) $(DEP_CPP_MOD_DL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_DL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_dll.obj"	"$(INTDIR)\mod_dll.sbr" : $(SOURCE) $(DEP_CPP_MOD_DL)\
 "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\mod_env.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_E=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_E=\
	".\sfio.h"\
	

"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_E=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_env.obj"	"$(INTDIR)\mod_env.sbr" : $(SOURCE) $(DEP_CPP_MOD_E)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_imap.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_I=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_I=\
	".\sfio.h"\
	

"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_I=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_imap.obj"	"$(INTDIR)\mod_imap.sbr" : $(SOURCE) $(DEP_CPP_MOD_I)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_include.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_IN=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_IN=\
	".\config.h"\
	".\modules\perl\mod_perl.h"\
	".\sfio.h"\
	

"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_IN=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_include.obj"	"$(INTDIR)\mod_include.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_log_config.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_L=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_L=\
	".\sfio.h"\
	

"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_L=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_log_config.obj"	"$(INTDIR)\mod_log_config.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_L) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_mime.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\mod_mime.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_M=\
	".\sfio.h"\
	

"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\mod_mime.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_mime.obj"	"$(INTDIR)\mod_mime.sbr" : $(SOURCE) $(DEP_CPP_MOD_M)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_negotiation.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_N=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_N=\
	".\sfio.h"\
	

"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_N=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\mod_negotiation.obj"	"$(INTDIR)\mod_negotiation.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_N) "$(INTDIR)"


!ENDIF 

SOURCE=.\mod_userdir.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MOD_U=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_U=\
	".\sfio.h"\
	

"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MOD_U=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\mod_userdir.obj"	"$(INTDIR)\mod_userdir.sbr" : $(SOURCE)\
 $(DEP_CPP_MOD_U) "$(INTDIR)"


!ENDIF 

SOURCE=.\nt\modules.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MODUL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MODUL=\
	".\sfio.h"\
	

"$(INTDIR)\modules.obj" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MODUL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\modules.obj"	"$(INTDIR)\modules.sbr" : $(SOURCE) $(DEP_CPP_MODUL)\
 "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\nt\multithread.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_MULTI=\
	".\conf.h"\
	".\multithread.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_MULTI=\
	".\conf.h"\
	".\multithread.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\multithread.obj"	"$(INTDIR)\multithread.sbr" : $(SOURCE)\
 $(DEP_CPP_MULTI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\nt\readdir.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_READD=\
	".\nt\readdir.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\readdir.obj" : $(SOURCE) $(DEP_CPP_READD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_READD=\
	".\nt\readdir.h"\
	

"$(INTDIR)\readdir.obj"	"$(INTDIR)\readdir.sbr" : $(SOURCE) $(DEP_CPP_READD)\
 "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\rfc1413.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_RFC14=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\rfc1413.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_RFC14=\
	".\sfio.h"\
	

"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_RFC14=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\rfc1413.h"\
	

"$(INTDIR)\rfc1413.obj"	"$(INTDIR)\rfc1413.sbr" : $(SOURCE) $(DEP_CPP_RFC14)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\nt\service.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_SERVI=\
	".\conf.h"\
	".\multithread.h"\
	".\nt\service.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_SERVI=\
	".\conf.h"\
	".\multithread.h"\
	".\nt\service.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\service.obj"	"$(INTDIR)\service.sbr" : $(SOURCE) $(DEP_CPP_SERVI)\
 "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\util.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_UTIL_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_UTIL_=\
	".\sfio.h"\
	

"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_UTIL_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\util.obj"	"$(INTDIR)\util.sbr" : $(SOURCE) $(DEP_CPP_UTIL_)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\util_date.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_UTIL_D=\
	".\conf.h"\
	".\regex\regex.h"\
	".\util_date.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_UTIL_D=\
	".\conf.h"\
	".\regex\regex.h"\
	".\util_date.h"\
	

"$(INTDIR)\util_date.obj"	"$(INTDIR)\util_date.sbr" : $(SOURCE)\
 $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ENDIF 

SOURCE=.\util_md5.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_UTIL_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\md5.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_md5.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_UTIL_M=\
	".\sfio.h"\
	

"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_UTIL_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\md5.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_md5.h"\
	

"$(INTDIR)\util_md5.obj"	"$(INTDIR)\util_md5.sbr" : $(SOURCE) $(DEP_CPP_UTIL_M)\
 "$(INTDIR)"


!ENDIF 

SOURCE=.\util_script.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_UTIL_S=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_UTIL_S=\
	".\sfio.h"\
	

"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_UTIL_S=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_script.h"\
	

"$(INTDIR)\util_script.obj"	"$(INTDIR)\util_script.sbr" : $(SOURCE)\
 $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ENDIF 

SOURCE=.\util_snprintf.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

DEP_CPP_UTIL_SN=\
	".\conf.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	

"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_SN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

DEP_CPP_UTIL_SN=\
	".\conf.h"\
	".\regex\regex.h"\
	

"$(INTDIR)\util_snprintf.obj"	"$(INTDIR)\util_snprintf.sbr" : $(SOURCE)\
 $(DEP_CPP_UTIL_SN) "$(INTDIR)"


!ENDIF 


!ENDIF 

