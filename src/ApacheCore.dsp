# Microsoft Developer Studio Project File - Name="ApacheCore" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=ApacheCore - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ApacheCore.mak".
!MESSAGE 
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

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheCore - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ".\ApacheCo"
# PROP BASE Intermediate_Dir ".\ApacheCo"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ".\CoreR"
# PROP Intermediate_Dir ".\CoreR"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I ".\regex" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /machine:I386

!ELSEIF  "$(CFG)" == "ApacheCore - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ".\ApacheC0"
# PROP BASE Intermediate_Dir ".\ApacheC0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ".\CoreD"
# PROP Intermediate_Dir ".\CoreD"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I ".\regex" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 regex\debug\regex.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /debug /machine:I386

!ENDIF 

# Begin Target

# Name "ApacheCore - Win32 Release"
# Name "ApacheCore - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=.\alloc.c
# End Source File
# Begin Source File

SOURCE=.\ApacheCore.def
# End Source File
# Begin Source File

SOURCE=.\buff.c
# End Source File
# Begin Source File

SOURCE=.\explain.c
# End Source File
# Begin Source File

SOURCE=.\nt\getopt.c
# End Source File
# Begin Source File

SOURCE=.\http_bprintf.c
# End Source File
# Begin Source File

SOURCE=.\http_config.c
# End Source File
# Begin Source File

SOURCE=.\http_core.c
# End Source File
# Begin Source File

SOURCE=.\http_log.c
# End Source File
# Begin Source File

SOURCE=.\http_main.c
# End Source File
# Begin Source File

SOURCE=.\http_protocol.c
# End Source File
# Begin Source File

SOURCE=.\http_request.c
# End Source File
# Begin Source File

SOURCE=.\md5c.c
# End Source File
# Begin Source File

SOURCE=.\mod_access.c
# End Source File
# Begin Source File

SOURCE=.\mod_actions.c
# End Source File
# Begin Source File

SOURCE=.\mod_alias.c
# End Source File
# Begin Source File

SOURCE=.\mod_asis.c
# End Source File
# Begin Source File

SOURCE=.\mod_auth.c
# End Source File
# Begin Source File

SOURCE=.\mod_autoindex.c
# End Source File
# Begin Source File

SOURCE=.\mod_browser.c
# End Source File
# Begin Source File

SOURCE=.\mod_cgi.c
# End Source File
# Begin Source File

SOURCE=.\mod_dir.c
# End Source File
# Begin Source File

SOURCE=.\nt\mod_dll.c
# End Source File
# Begin Source File

SOURCE=.\mod_env.c
# End Source File
# Begin Source File

SOURCE=.\mod_imap.c
# End Source File
# Begin Source File

SOURCE=.\mod_include.c
# End Source File
# Begin Source File

SOURCE=.\mod_log_config.c
# End Source File
# Begin Source File

SOURCE=.\mod_mime.c
# End Source File
# Begin Source File

SOURCE=.\mod_negotiation.c
# End Source File
# Begin Source File

SOURCE=.\mod_userdir.c
# End Source File
# Begin Source File

SOURCE=.\nt\modules.c
# End Source File
# Begin Source File

SOURCE=.\nt\multithread.c
# End Source File
# Begin Source File

SOURCE=.\nt\readdir.c
# End Source File
# Begin Source File

SOURCE=.\rfc1413.c
# End Source File
# Begin Source File

SOURCE=.\nt\service.c
# End Source File
# Begin Source File

SOURCE=.\util.c
# End Source File
# Begin Source File

SOURCE=.\util_date.c
# End Source File
# Begin Source File

SOURCE=.\util_md5.c
# End Source File
# Begin Source File

SOURCE=.\util_script.c
# End Source File
# Begin Source File

SOURCE=.\util_snprintf.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Source File

SOURCE=.\alloc.h
# End Source File
# Begin Source File

SOURCE=.\buff.h
# End Source File
# Begin Source File

SOURCE=.\conf.h
# End Source File
# Begin Source File

SOURCE=.\explain.h
# End Source File
# Begin Source File

SOURCE=.\nt\getopt.h
# End Source File
# Begin Source File

SOURCE=.\http_conf_globals.h
# End Source File
# Begin Source File

SOURCE=.\http_config.h
# End Source File
# Begin Source File

SOURCE=.\http_core.h
# End Source File
# Begin Source File

SOURCE=.\http_log.h
# End Source File
# Begin Source File

SOURCE=.\http_main.h
# End Source File
# Begin Source File

SOURCE=.\http_protocol.h
# End Source File
# Begin Source File

SOURCE=.\http_request.h
# End Source File
# Begin Source File

SOURCE=.\httpd.h
# End Source File
# Begin Source File

SOURCE=.\md5.h
# End Source File
# Begin Source File

SOURCE=.\mod_mime.h
# End Source File
# Begin Source File

SOURCE=.\multithread.h
# End Source File
# Begin Source File

SOURCE=.\nt\readdir.h
# End Source File
# Begin Source File

SOURCE=.\rfc1413.h
# End Source File
# Begin Source File

SOURCE=.\scoreboard.h
# End Source File
# Begin Source File

SOURCE=.\nt\service.h
# End Source File
# Begin Source File

SOURCE=.\util_date.h
# End Source File
# Begin Source File

SOURCE=.\util_md5.h
# End Source File
# Begin Source File

SOURCE=.\util_script.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
