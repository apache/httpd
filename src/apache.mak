# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

!IF "$(CFG)" == ""
CFG=APACHE - WIN32 DEBUG
!MESSAGE No configuration specified.  Defaulting to APACHE - WIN32 DEBUG.
!ENDIF 

!IF "$(CFG)" != "apache - Win32 Release" && "$(CFG)" != "apache - Win32 Debug"\
 && "$(CFG)" != "apache - Win32 Pre" && "$(CFG)" != "apache - Win32 Profile"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "apache.mak" CFG="APACHE - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "apache - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "apache - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE "apache - Win32 Pre" (based on "Win32 (x86) Console Application")
!MESSAGE "apache - Win32 Profile" (based on "Win32 (x86) Console Application")
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
# PROP Target_Last_Scanned "apache - Win32 Profile"
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "apache - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\apache.exe"

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
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_env.obj"
	-@erase "$(INTDIR)\mod_imap.obj"
	-@erase "$(INTDIR)\mod_include.obj"
	-@erase "$(INTDIR)\mod_log_config.obj"
	-@erase "$(INTDIR)\mod_mime.obj"
	-@erase "$(INTDIR)\mod_negotiation.obj"
	-@erase "$(INTDIR)\mod_userdir.obj"
	-@erase "$(INTDIR)\modules.obj"
	-@erase "$(INTDIR)\multithread.obj"
	-@erase "$(INTDIR)\nt.obj"
	-@erase "$(INTDIR)\ntcrypt.obj"
	-@erase "$(INTDIR)\rfc1413.obj"
	-@erase "$(INTDIR)\service.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_date.obj"
	-@erase "$(INTDIR)\util_md5.obj"
	-@erase "$(INTDIR)\util_script.obj"
	-@erase "$(INTDIR)\util_snprintf.obj"
	-@erase "$(OUTDIR)\apache.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "./regex" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "./regex" /D "WIN32" /D "NDEBUG" /D\
 "_CONSOLE" /Fp"$(INTDIR)/apache.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 modules/proxy/Release/proxy.lib regex/Release/regex.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=modules/proxy/Release/proxy.lib regex/Release/regex.lib\
 wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/apache.pdb" /machine:I386 /out:"$(OUTDIR)/apache.exe" 
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
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\nt.obj" \
	"$(INTDIR)\ntcrypt.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "apache - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\apache.exe" "$(OUTDIR)\apache.bsc"

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
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_browser.sbr"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_cgi.sbr"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_dir.sbr"
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
	-@erase "$(INTDIR)\nt.obj"
	-@erase "$(INTDIR)\nt.sbr"
	-@erase "$(INTDIR)\ntcrypt.obj"
	-@erase "$(INTDIR)\ntcrypt.sbr"
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
	-@erase "$(OUTDIR)\apache.bsc"
	-@erase "$(OUTDIR)\apache.exe"
	-@erase "$(OUTDIR)\apache.ilk"
	-@erase "$(OUTDIR)\apache.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FR /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG"\
 /D "_CONSOLE" /FR"$(INTDIR)/" /Fp"$(INTDIR)/apache.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\Debug/
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/apache.bsc" 
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
	"$(INTDIR)\mod_browser.sbr" \
	"$(INTDIR)\mod_cgi.sbr" \
	"$(INTDIR)\mod_dir.sbr" \
	"$(INTDIR)\mod_env.sbr" \
	"$(INTDIR)\mod_imap.sbr" \
	"$(INTDIR)\mod_include.sbr" \
	"$(INTDIR)\mod_log_config.sbr" \
	"$(INTDIR)\mod_mime.sbr" \
	"$(INTDIR)\mod_negotiation.sbr" \
	"$(INTDIR)\mod_userdir.sbr" \
	"$(INTDIR)\modules.sbr" \
	"$(INTDIR)\multithread.sbr" \
	"$(INTDIR)\nt.sbr" \
	"$(INTDIR)\ntcrypt.sbr" \
	"$(INTDIR)\rfc1413.sbr" \
	"$(INTDIR)\service.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\util_date.sbr" \
	"$(INTDIR)\util_md5.sbr" \
	"$(INTDIR)\util_script.sbr" \
	"$(INTDIR)\util_snprintf.sbr"

"$(OUTDIR)\apache.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
# ADD LINK32 modules/proxy/Debug/proxy.lib regex/Debug/regex.lib nt/Debug/nt.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
LINK32_FLAGS=modules/proxy/Debug/proxy.lib regex/Debug/regex.lib\
 nt/Debug/nt.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)/apache.pdb" /debug /machine:I386 /out:"$(OUTDIR)/apache.exe" 
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
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\nt.obj" \
	"$(INTDIR)\ntcrypt.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "apache__"
# PROP BASE Intermediate_Dir "apache__"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "apache__"
# PROP Intermediate_Dir "apache__"
# PROP Target_Dir ""
OUTDIR=.\apache__
INTDIR=.\apache__

ALL : "$(OUTDIR)\apache.exe" "$(OUTDIR)\apache.bsc"

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
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_browser.sbr"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_cgi.sbr"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_dir.sbr"
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
	-@erase "$(INTDIR)\nt.obj"
	-@erase "$(INTDIR)\nt.sbr"
	-@erase "$(INTDIR)\ntcrypt.obj"
	-@erase "$(INTDIR)\ntcrypt.sbr"
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
	-@erase "$(OUTDIR)\apache.bsc"
	-@erase "$(OUTDIR)\apache.exe"
	-@erase "$(OUTDIR)\apache.ilk"
	-@erase "$(OUTDIR)\apache.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FR /YX /c
# ADD CPP /nologo /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FR /YX /P
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG"\
 /D "_CONSOLE" /FR"$(INTDIR)/" /Fp"$(INTDIR)/apache.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /P 
CPP_OBJS=.\apache__/
CPP_SBRS=.\apache__/
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/apache.bsc" 
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
	"$(INTDIR)\mod_browser.sbr" \
	"$(INTDIR)\mod_cgi.sbr" \
	"$(INTDIR)\mod_dir.sbr" \
	"$(INTDIR)\mod_env.sbr" \
	"$(INTDIR)\mod_imap.sbr" \
	"$(INTDIR)\mod_include.sbr" \
	"$(INTDIR)\mod_log_config.sbr" \
	"$(INTDIR)\mod_mime.sbr" \
	"$(INTDIR)\mod_negotiation.sbr" \
	"$(INTDIR)\mod_userdir.sbr" \
	"$(INTDIR)\modules.sbr" \
	"$(INTDIR)\multithread.sbr" \
	"$(INTDIR)\nt.sbr" \
	"$(INTDIR)\ntcrypt.sbr" \
	"$(INTDIR)\rfc1413.sbr" \
	"$(INTDIR)\service.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\util_date.sbr" \
	"$(INTDIR)\util_md5.sbr" \
	"$(INTDIR)\util_script.sbr" \
	"$(INTDIR)\util_snprintf.sbr"

"$(OUTDIR)\apache.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 regex/Debug/regex.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
# ADD LINK32 regex/Debug/regex.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
LINK32_FLAGS=regex/Debug/regex.lib wsock32.lib kernel32.lib user32.lib\
 gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib\
 oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console\
 /incremental:yes /pdb:"$(OUTDIR)/apache.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)/apache.exe" 
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
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\nt.obj" \
	"$(INTDIR)\ntcrypt.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "apache_0"
# PROP BASE Intermediate_Dir "apache_0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "apache_0"
# PROP Intermediate_Dir "apache_0"
# PROP Target_Dir ""
OUTDIR=.\apache_0
INTDIR=.\apache_0

ALL : "$(OUTDIR)\apache.exe" "$(OUTDIR)\apache.bsc"

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
	-@erase "$(INTDIR)\mod_browser.obj"
	-@erase "$(INTDIR)\mod_browser.sbr"
	-@erase "$(INTDIR)\mod_cgi.obj"
	-@erase "$(INTDIR)\mod_cgi.sbr"
	-@erase "$(INTDIR)\mod_dir.obj"
	-@erase "$(INTDIR)\mod_dir.sbr"
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
	-@erase "$(INTDIR)\nt.obj"
	-@erase "$(INTDIR)\nt.sbr"
	-@erase "$(INTDIR)\ntcrypt.obj"
	-@erase "$(INTDIR)\ntcrypt.sbr"
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
	-@erase "$(OUTDIR)\apache.bsc"
	-@erase "$(OUTDIR)\apache.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FR /YX /c
# ADD CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FR /YX /c
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /I "./regex" /D "WIN32" /D "_DEBUG"\
 /D "_CONSOLE" /FR"$(INTDIR)/" /Fp"$(INTDIR)/apache.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\apache_0/
CPP_SBRS=.\apache_0/
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/apache.bsc" 
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
	"$(INTDIR)\mod_browser.sbr" \
	"$(INTDIR)\mod_cgi.sbr" \
	"$(INTDIR)\mod_dir.sbr" \
	"$(INTDIR)\mod_env.sbr" \
	"$(INTDIR)\mod_imap.sbr" \
	"$(INTDIR)\mod_include.sbr" \
	"$(INTDIR)\mod_log_config.sbr" \
	"$(INTDIR)\mod_mime.sbr" \
	"$(INTDIR)\mod_negotiation.sbr" \
	"$(INTDIR)\mod_userdir.sbr" \
	"$(INTDIR)\modules.sbr" \
	"$(INTDIR)\multithread.sbr" \
	"$(INTDIR)\nt.sbr" \
	"$(INTDIR)\ntcrypt.sbr" \
	"$(INTDIR)\rfc1413.sbr" \
	"$(INTDIR)\service.sbr" \
	"$(INTDIR)\util.sbr" \
	"$(INTDIR)\util_date.sbr" \
	"$(INTDIR)\util_md5.sbr" \
	"$(INTDIR)\util_script.sbr" \
	"$(INTDIR)\util_snprintf.sbr"

"$(OUTDIR)\apache.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LINK32=link.exe
# ADD BASE LINK32 regex/Debug/regex.lib nt/Debug/nt.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
# ADD LINK32 modules/proxy/Debug/proxy.lib regex/Debug/regex.lib nt/Debug/nt.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /profile /debug /machine:I386
LINK32_FLAGS=modules/proxy/Debug/proxy.lib regex/Debug/regex.lib\
 nt/Debug/nt.lib wsock32.lib kernel32.lib user32.lib gdi32.lib winspool.lib\
 comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib\
 odbc32.lib odbccp32.lib /nologo /subsystem:console /profile /debug\
 /machine:I386 /out:"$(OUTDIR)/apache.exe" 
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
	"$(INTDIR)\mod_browser.obj" \
	"$(INTDIR)\mod_cgi.obj" \
	"$(INTDIR)\mod_dir.obj" \
	"$(INTDIR)\mod_env.obj" \
	"$(INTDIR)\mod_imap.obj" \
	"$(INTDIR)\mod_include.obj" \
	"$(INTDIR)\mod_log_config.obj" \
	"$(INTDIR)\mod_mime.obj" \
	"$(INTDIR)\mod_negotiation.obj" \
	"$(INTDIR)\mod_userdir.obj" \
	"$(INTDIR)\modules.obj" \
	"$(INTDIR)\multithread.obj" \
	"$(INTDIR)\nt.obj" \
	"$(INTDIR)\ntcrypt.obj" \
	"$(INTDIR)\rfc1413.obj" \
	"$(INTDIR)\service.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_date.obj" \
	"$(INTDIR)\util_md5.obj" \
	"$(INTDIR)\util_script.obj" \
	"$(INTDIR)\util_snprintf.obj"

"$(OUTDIR)\apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "apache - Win32 Release"
# Name "apache - Win32 Debug"
# Name "apache - Win32 Pre"
# Name "apache - Win32 Profile"

!IF  "$(CFG)" == "apache - Win32 Release"

!ELSEIF  "$(CFG)" == "apache - Win32 Debug"

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\util_snprintf.c
DEP_CPP_UTIL_=\
	".\./regex\regex.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"

"$(INTDIR)\util_snprintf.sbr" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"

"$(INTDIR)\util_snprintf.sbr" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\util_snprintf.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"

"$(INTDIR)\util_snprintf.sbr" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\buff.c

!IF  "$(CFG)" == "apache - Win32 Release"

DEP_CPP_BUFF_=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"

DEP_CPP_BUFF_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"

"$(INTDIR)\buff.sbr" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"

DEP_CPP_BUFF_=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"

"$(INTDIR)\buff.sbr" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"

DEP_CPP_BUFF_=\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\buff.obj" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"

"$(INTDIR)\buff.sbr" : $(SOURCE) $(DEP_CPP_BUFF_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\explain.c
DEP_CPP_EXPLA=\
	".\explain.h"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"

"$(INTDIR)\explain.sbr" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"

"$(INTDIR)\explain.sbr" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\explain.obj" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"

"$(INTDIR)\explain.sbr" : $(SOURCE) $(DEP_CPP_EXPLA) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_bprintf.c
DEP_CPP_HTTP_=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"

"$(INTDIR)\http_bprintf.sbr" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"

"$(INTDIR)\http_bprintf.sbr" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_bprintf.obj" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"

"$(INTDIR)\http_bprintf.sbr" : $(SOURCE) $(DEP_CPP_HTTP_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_config.c
DEP_CPP_HTTP_C=\
	".\./regex\regex.h"\
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
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"

"$(INTDIR)\http_config.sbr" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"

"$(INTDIR)\http_config.sbr" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_config.obj" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"

"$(INTDIR)\http_config.sbr" : $(SOURCE) $(DEP_CPP_HTTP_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_core.c
DEP_CPP_HTTP_CO=\
	".\./regex\regex.h"\
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
	".\rfc1413.h"\
	".\scoreboard.h"\
	".\util_md5.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"

"$(INTDIR)\http_core.sbr" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"

"$(INTDIR)\http_core.sbr" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_core.obj" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"

"$(INTDIR)\http_core.sbr" : $(SOURCE) $(DEP_CPP_HTTP_CO) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_log.c
DEP_CPP_HTTP_L=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"

"$(INTDIR)\http_log.sbr" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"

"$(INTDIR)\http_log.sbr" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_log.obj" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"

"$(INTDIR)\http_log.sbr" : $(SOURCE) $(DEP_CPP_HTTP_L) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_main.c
DEP_CPP_HTTP_M=\
	".\./regex\regex.h"\
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
	".\NT\service.h"\
	".\scoreboard.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"

"$(INTDIR)\http_main.sbr" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"

"$(INTDIR)\http_main.sbr" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_main.obj" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"

"$(INTDIR)\http_main.sbr" : $(SOURCE) $(DEP_CPP_HTTP_M) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_protocol.c
DEP_CPP_HTTP_P=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	".\util_date.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"

"$(INTDIR)\http_protocol.sbr" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"

"$(INTDIR)\http_protocol.sbr" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_protocol.obj" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"

"$(INTDIR)\http_protocol.sbr" : $(SOURCE) $(DEP_CPP_HTTP_P) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\http_request.c
DEP_CPP_HTTP_R=\
	".\./regex\regex.h"\
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
	".\scoreboard.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"

"$(INTDIR)\http_request.sbr" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"

"$(INTDIR)\http_request.sbr" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\http_request.obj" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"

"$(INTDIR)\http_request.sbr" : $(SOURCE) $(DEP_CPP_HTTP_R) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\md5c.c
DEP_CPP_MD5C_=\
	".\md5.h"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"

"$(INTDIR)\md5c.sbr" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"

"$(INTDIR)\md5c.sbr" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\md5c.obj" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"

"$(INTDIR)\md5c.sbr" : $(SOURCE) $(DEP_CPP_MD5C_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_access.c
DEP_CPP_MOD_A=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"

"$(INTDIR)\mod_access.sbr" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"

"$(INTDIR)\mod_access.sbr" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_access.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"

"$(INTDIR)\mod_access.sbr" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_actions.c
DEP_CPP_MOD_AC=\
	".\./regex\regex.h"\
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
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"

"$(INTDIR)\mod_actions.sbr" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"

"$(INTDIR)\mod_actions.sbr" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_actions.obj" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"

"$(INTDIR)\mod_actions.sbr" : $(SOURCE) $(DEP_CPP_MOD_AC) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_alias.c
DEP_CPP_MOD_AL=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"

"$(INTDIR)\mod_alias.sbr" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"

"$(INTDIR)\mod_alias.sbr" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_alias.obj" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"

"$(INTDIR)\mod_alias.sbr" : $(SOURCE) $(DEP_CPP_MOD_AL) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_asis.c
DEP_CPP_MOD_AS=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\http_protocol.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"

"$(INTDIR)\mod_asis.sbr" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"

"$(INTDIR)\mod_asis.sbr" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_asis.obj" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"

"$(INTDIR)\mod_asis.sbr" : $(SOURCE) $(DEP_CPP_MOD_AS) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_auth.c
DEP_CPP_MOD_AU=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_protocol.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"

"$(INTDIR)\mod_auth.sbr" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"

"$(INTDIR)\mod_auth.sbr" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_auth.obj" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"

"$(INTDIR)\mod_auth.sbr" : $(SOURCE) $(DEP_CPP_MOD_AU) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\alloc.c

!IF  "$(CFG)" == "apache - Win32 Release"

DEP_CPP_ALLOC=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\conf.h"\
	".\multithread.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"

DEP_CPP_ALLOC=\
	".\alloc.h"\
	".\conf.h"\
	".\multithread.h"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"

"$(INTDIR)\alloc.sbr" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"

DEP_CPP_ALLOC=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\conf.h"\
	".\multithread.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"

"$(INTDIR)\alloc.sbr" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"

DEP_CPP_ALLOC=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\conf.h"\
	".\multithread.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\alloc.obj" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"

"$(INTDIR)\alloc.sbr" : $(SOURCE) $(DEP_CPP_ALLOC) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_script.c
DEP_CPP_UTIL_S=\
	".\./regex\regex.h"\
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
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"

"$(INTDIR)\util_script.sbr" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"

"$(INTDIR)\util_script.sbr" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\util_script.obj" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"

"$(INTDIR)\util_script.sbr" : $(SOURCE) $(DEP_CPP_UTIL_S) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_cgi.c
DEP_CPP_MOD_C=\
	".\./regex\regex.h"\
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
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"

"$(INTDIR)\mod_cgi.sbr" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"

"$(INTDIR)\mod_cgi.sbr" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_cgi.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"

"$(INTDIR)\mod_cgi.sbr" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_dir.c
DEP_CPP_MOD_D=\
	".\./regex\regex.h"\
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
	".\nt\dirent.h"\
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"

"$(INTDIR)\mod_dir.sbr" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"

"$(INTDIR)\mod_dir.sbr" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_dir.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"

"$(INTDIR)\mod_dir.sbr" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_env.c
DEP_CPP_MOD_E=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"

"$(INTDIR)\mod_env.sbr" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"

"$(INTDIR)\mod_env.sbr" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_env.obj" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"

"$(INTDIR)\mod_env.sbr" : $(SOURCE) $(DEP_CPP_MOD_E) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_imap.c
DEP_CPP_MOD_I=\
	".\./regex\regex.h"\
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
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"

"$(INTDIR)\mod_imap.sbr" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"

"$(INTDIR)\mod_imap.sbr" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_imap.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"

"$(INTDIR)\mod_imap.sbr" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_include.c
DEP_CPP_MOD_IN=\
	".\./regex\regex.h"\
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
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_IN=\
	".\config.h"\
	".\modules\perl\mod_perl.h"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"

"$(INTDIR)\mod_include.sbr" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"

"$(INTDIR)\mod_include.sbr" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_include.obj" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"

"$(INTDIR)\mod_include.sbr" : $(SOURCE) $(DEP_CPP_MOD_IN) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_log_config.c
DEP_CPP_MOD_L=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"

"$(INTDIR)\mod_log_config.sbr" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"

"$(INTDIR)\mod_log_config.sbr" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_log_config.obj" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"

"$(INTDIR)\mod_log_config.sbr" : $(SOURCE) $(DEP_CPP_MOD_L) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_mime.c
DEP_CPP_MOD_M=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"

"$(INTDIR)\mod_mime.sbr" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"

"$(INTDIR)\mod_mime.sbr" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_mime.obj" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"

"$(INTDIR)\mod_mime.sbr" : $(SOURCE) $(DEP_CPP_MOD_M) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_negotiation.c
DEP_CPP_MOD_N=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\http_core.h"\
	".\http_log.h"\
	".\http_request.h"\
	".\httpd.h"\
	".\nt\dirent.h"\
	".\util_script.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"

"$(INTDIR)\mod_negotiation.sbr" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"

"$(INTDIR)\mod_negotiation.sbr" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_negotiation.obj" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"

"$(INTDIR)\mod_negotiation.sbr" : $(SOURCE) $(DEP_CPP_MOD_N) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_userdir.c
DEP_CPP_MOD_U=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"

"$(INTDIR)\mod_userdir.sbr" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"

"$(INTDIR)\mod_userdir.sbr" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_userdir.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"

"$(INTDIR)\mod_userdir.sbr" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\rfc1413.c
DEP_CPP_RFC14=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_log.h"\
	".\http_main.h"\
	".\httpd.h"\
	".\rfc1413.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"

"$(INTDIR)\rfc1413.sbr" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"

"$(INTDIR)\rfc1413.sbr" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\rfc1413.obj" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"

"$(INTDIR)\rfc1413.sbr" : $(SOURCE) $(DEP_CPP_RFC14) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util.c
DEP_CPP_UTIL_C=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_conf_globals.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"

"$(INTDIR)\util.sbr" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"

"$(INTDIR)\util.sbr" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"

"$(INTDIR)\util.sbr" : $(SOURCE) $(DEP_CPP_UTIL_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_date.c
DEP_CPP_UTIL_D=\
	".\util_date.h"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"

"$(INTDIR)\util_date.sbr" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"

"$(INTDIR)\util_date.sbr" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\util_date.obj" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"

"$(INTDIR)\util_date.sbr" : $(SOURCE) $(DEP_CPP_UTIL_D) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\util_md5.c
DEP_CPP_UTIL_M=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\httpd.h"\
	".\md5.h"\
	".\util_md5.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"

"$(INTDIR)\util_md5.sbr" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"

"$(INTDIR)\util_md5.sbr" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\util_md5.obj" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"

"$(INTDIR)\util_md5.sbr" : $(SOURCE) $(DEP_CPP_UTIL_M) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_browser.c
DEP_CPP_MOD_B=\
	".\./regex\regex.h"\
	".\alloc.h"\
	".\buff.h"\
	".\conf.h"\
	".\http_config.h"\
	".\httpd.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"

"$(INTDIR)\mod_browser.sbr" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"

"$(INTDIR)\mod_browser.sbr" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


"$(INTDIR)\mod_browser.obj" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"

"$(INTDIR)\mod_browser.sbr" : $(SOURCE) $(DEP_CPP_MOD_B) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\NT\modules.c
NODEP_CPP_MODUL=\
	".\NT\http_config.h"\
	".\NT\httpd.h"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\modules.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\modules.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\modules.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\modules.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\modules.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\modules.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\modules.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\NT\multithread.c
DEP_CPP_MULTI=\
	".\./regex\regex.h"\
	".\conf.h"\
	".\multithread.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\multithread.sbr" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\multithread.obj" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\multithread.sbr" : $(SOURCE) $(DEP_CPP_MULTI) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


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

SOURCE=.\NT\service.c
DEP_CPP_SERVI=\
	".\./regex\regex.h"\
	".\conf.h"\
	".\multithread.h"\
	".\NT\service.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\service.sbr" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\service.obj" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\service.sbr" : $(SOURCE) $(DEP_CPP_SERVI) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


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

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\getopt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\getopt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


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

SOURCE=.\nt\nt.c
DEP_CPP_NT_C46=\
	".\nt\dirent.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\nt.obj" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\nt.obj" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\nt.sbr" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\nt.obj" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\nt.sbr" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\nt.obj" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\nt.sbr" : $(SOURCE) $(DEP_CPP_NT_C46) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\nt\ntcrypt.c

!IF  "$(CFG)" == "apache - Win32 Release"


"$(INTDIR)\ntcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "apache - Win32 Debug"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ntcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ntcrypt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Pre"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ntcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ntcrypt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ELSEIF  "$(CFG)" == "apache - Win32 Profile"


BuildCmds= \
	$(CPP) $(CPP_PROJ) $(SOURCE) \
	

"$(INTDIR)\ntcrypt.obj" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

"$(INTDIR)\ntcrypt.sbr" : $(SOURCE) "$(INTDIR)"
   $(BuildCmds)

!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
