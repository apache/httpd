# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=ApacheCore - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to ApacheCore - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheCore - Win32 Release" && "$(CFG)" !=\
 "ApacheCore - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak" CFG="ApacheCore - Win32 Debug"
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
################################################################################
# Begin Project
# PROP Target_Last_Scanned "ApacheCore - Win32 Debug"
MTL=mktyplib.exe
RSC=rc.exe
CPP=cl.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ApacheCo"
# PROP BASE Intermediate_Dir "ApacheCo"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "CoreR"
# PROP Intermediate_Dir "CoreR"
# PROP Target_Dir ""
OUTDIR=.\CoreR
INTDIR=.\CoreR

ALL : "$(OUTDIR)\ApacheCore.dll"

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
	-@erase "$(INTDIR)\modules_dll.obj"
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\readdir.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_snprintf.obj"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "regex" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "regex" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)/ApacheCore.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\CoreR/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheCore.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /machine:I386
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)/ApacheCore.pdb" /machine:I386 /def:".\ApacheCore.def"\
 /out:"$(OUTDIR)/ApacheCore.dll" /implib:"$(OUTDIR)/ApacheCore.lib" 
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
	"$(INTDIR)\modules_dll.obj" \
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

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ApacheC0"
# PROP BASE Intermediate_Dir "ApacheC0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "CoreD"
# PROP Intermediate_Dir "CoreD"
# PROP Target_Dir ""
OUTDIR=.\CoreD
INTDIR=.\CoreD

ALL : "$(OUTDIR)\ApacheCore.dll" "$(OUTDIR)\ApacheCore.bsc"

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
	-@erase "$(INTDIR)\modules_dll.obj"
	-@erase "$(INTDIR)\modules_dll.sbr"
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
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\ApacheCore.bsc"
	-@erase "$(OUTDIR)\ApacheCore.dll"
	-@erase "$(OUTDIR)\ApacheCore.exp"
	-@erase "$(OUTDIR)\ApacheCore.ilk"
	-@erase "$(OUTDIR)\ApacheCore.lib"
	-@erase "$(OUTDIR)\ApacheCore.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "regex" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /c
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "regex" /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /FR"$(INTDIR)/" /Fp"$(INTDIR)/ApacheCore.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\CoreD/
CPP_SBRS=.\CoreD/
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheCore.bsc" 
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
	"$(INTDIR)\modules_dll.sbr" \
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
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 regex\debug\regex.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /debug /machine:I386
LINK32_FLAGS=regex\debug\regex.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)/ApacheCore.pdb" /debug /machine:I386\
 /def:".\ApacheCore.def" /out:"$(OUTDIR)/ApacheCore.dll"\
 /implib:"$(OUTDIR)/ApacheCore.lib" 
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
	"$(INTDIR)\modules_dll.obj" \
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

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "ApacheCore - Win32 Release"
# Name "ApacheCore - Win32 Debug"

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\http_main.c
DEP_CPP_HTTP_=\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"

"$(INTDIR)\http_main.sbr" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\buff.c
DEP_CPP_BUFF_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_BUFF_=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"

"$(INTDIR)\buff.sbr" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\alloc.c
DEP_CPP_ALLOC=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\multithread.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_ALLOC=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"

"$(INTDIR)\alloc.sbr" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_log.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_L=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"

"$(INTDIR)\http_log.sbr" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_config.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_C=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"

"$(INTDIR)\http_config.sbr" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_snprintf.c
DEP_CPP_UTIL_=\
	".\conf.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"

"$(INTDIR)\util_snprintf.sbr" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_core.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_CO=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"

"$(INTDIR)\http_core.sbr" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util.c
DEP_CPP_UTIL_C=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_UTIL_C=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"

"$(INTDIR)\util.sbr" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\multithread.c
DEP_CPP_MULTI=\
	".\conf.h"\
	".\multithread.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\multithread.sbr" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_protocol.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_P=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"

"$(INTDIR)\http_protocol.sbr" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_request.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_R=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"

"$(INTDIR)\http_request.sbr" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\service.c
DEP_CPP_SERVI=\
	".\conf.h"\
	".\multithread.h"\
	".\nt\service.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\service.sbr" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\getopt.c

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\readdir.c
DEP_CPP_READD=\
	".\nt\readdir.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\readdir.obj" : $(SOURCE) $(DEP_CPP_READD) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\readdir.obj" : $(SOURCE) $(DEP_CPP_READD) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\readdir.sbr" : $(SOURCE) $(DEP_CPP_READD) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\rfc1413.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_RFC14=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"

"$(INTDIR)\rfc1413.sbr" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\md5c.c
DEP_CPP_MD5C_=\
	".\md5.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"

"$(INTDIR)\md5c.sbr" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_md5.c
DEP_CPP_UTIL_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\md5.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	".\util_md5.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_UTIL_M=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"

"$(INTDIR)\util_md5.sbr" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_date.c
DEP_CPP_UTIL_D=\
	".\util_date.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"

"$(INTDIR)\util_date.sbr" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_bprintf.c
DEP_CPP_HTTP_B=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_HTTP_B=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_B) "$(INTDIR)"

"$(INTDIR)\http_bprintf.sbr" : $(SOURCE) $(DEP_CPP_HTTP_B) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\modules_dll.c
DEP_CPP_MODUL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MODUL=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\modules_dll.obj" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\modules_dll.obj" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\modules_dll.sbr" : $(SOURCE) $(DEP_CPP_MODUL) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\mod_dll.c
DEP_CPP_MOD_D=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_D=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_dll.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\mod_dll.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\mod_dll.sbr" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\explain.c
DEP_CPP_EXPLA=\
	".\explain.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"

"$(INTDIR)\explain.sbr" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_script.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_UTIL_S=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"

"$(INTDIR)\util_script.sbr" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\ApacheCore.def

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_env.c
DEP_CPP_MOD_E=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_E=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"

"$(INTDIR)\mod_env.sbr" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_log_config.c
DEP_CPP_MOD_L=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_L=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"

"$(INTDIR)\mod_log_config.sbr" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_negotiation.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_N=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"

"$(INTDIR)\mod_negotiation.sbr" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_mime.c
DEP_CPP_MOD_M=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_M=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"

"$(INTDIR)\mod_mime.sbr" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_cgi.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_C=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"

"$(INTDIR)\mod_cgi.sbr" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_autoindex.c
DEP_CPP_MOD_A=\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_A=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"

"$(INTDIR)\mod_autoindex.sbr" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_dir.c
DEP_CPP_MOD_DI=\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_DI=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_DI) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_DI) "$(INTDIR)"

"$(INTDIR)\mod_dir.sbr" : $(SOURCE) $(DEP_CPP_MOD_DI) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_include.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_I=\
	".\config.h"\
	".\modules\perl\mod_perl.h"\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"

"$(INTDIR)\mod_include.sbr" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_imap.c
DEP_CPP_MOD_IM=\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_IM=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_IM) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_IM) "$(INTDIR)"

"$(INTDIR)\mod_imap.sbr" : $(SOURCE) $(DEP_CPP_MOD_IM) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_asis.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_AS=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"

"$(INTDIR)\mod_asis.sbr" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_actions.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_AC=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"

"$(INTDIR)\mod_actions.sbr" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_userdir.c
DEP_CPP_MOD_U=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_U=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"

"$(INTDIR)\mod_userdir.sbr" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_alias.c
DEP_CPP_MOD_AL=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_AL=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"

"$(INTDIR)\mod_alias.sbr" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_auth.c
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_AU=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"

"$(INTDIR)\mod_auth.sbr" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_access.c
DEP_CPP_MOD_ACC=\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_ACC=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_ACC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_ACC) "$(INTDIR)"

"$(INTDIR)\mod_access.sbr" : $(SOURCE) $(DEP_CPP_MOD_ACC) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_browser.c
DEP_CPP_MOD_B=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	".\nt\readdir.h"\
	".\regex\regex.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_B=\
	".\sfio.h"\
	

!IF  "$(CFG)" == "ApacheCore - Win32 Release"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"

"$(INTDIR)\mod_browser.sbr" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
