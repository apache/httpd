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
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I ".\regex" /I ".\core" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 regex\release\regex.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /machine:I386

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
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I ".\regex" /I ".\core" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /FD /c
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

SOURCE=.\core\alloc.c
# End Source File
# Begin Source File

SOURCE=.\ApacheCore.def
# End Source File
# Begin Source File

SOURCE=.\core\buff.c
# End Source File
# Begin Source File

SOURCE=.\core\explain.c
# End Source File
# Begin Source File

SOURCE=.\core\fnmatch.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\getopt.c
# End Source File
# Begin Source File

SOURCE=.\core\http_bprintf.c
# End Source File
# Begin Source File

SOURCE=.\core\http_config.c
# End Source File
# Begin Source File

SOURCE=.\core\http_core.c
# End Source File
# Begin Source File

SOURCE=.\core\http_log.c
# End Source File
# Begin Source File

SOURCE=.\core\http_main.c
# End Source File
# Begin Source File

SOURCE=.\core\http_protocol.c
# End Source File
# Begin Source File

SOURCE=.\core\http_request.c
# End Source File
# Begin Source File

SOURCE=.\core\md5c.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_access.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_actions.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_alias.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_asis.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_auth.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_autoindex.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_cgi.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_dir.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\mod_dll.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_env.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_imap.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_include.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\mod_isapi.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_log_config.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_mime.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_negotiation.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_setenvif.c
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_userdir.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\modules.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\multithread.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\readdir.c
# End Source File
# Begin Source File

SOURCE=.\core\rfc1413.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\service.c
# End Source File
# Begin Source File

SOURCE=.\core\util.c
# End Source File
# Begin Source File

SOURCE=.\core\util_date.c
# End Source File
# Begin Source File

SOURCE=.\core\util_md5.c
# End Source File
# Begin Source File

SOURCE=.\core\util_script.c
# End Source File
# Begin Source File

SOURCE=.\core\util_snprintf.c
# End Source File
# Begin Source File

SOURCE=.\os\win32\util_win32.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl;fi;fd"
# Begin Source File

SOURCE=.\core\alloc.h
# End Source File
# Begin Source File

SOURCE=.\core\buff.h
# End Source File
# Begin Source File

SOURCE=.\core\conf.h
# End Source File
# Begin Source File

SOURCE=.\core\explain.h
# End Source File
# Begin Source File

SOURCE=.\core\fnmatch.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\getopt.h
# End Source File
# Begin Source File

SOURCE=.\core\http_conf_globals.h
# End Source File
# Begin Source File

SOURCE=.\core\http_config.h
# End Source File
# Begin Source File

SOURCE=.\core\http_core.h
# End Source File
# Begin Source File

SOURCE=.\core\http_log.h
# End Source File
# Begin Source File

SOURCE=.\core\http_main.h
# End Source File
# Begin Source File

SOURCE=.\core\http_protocol.h
# End Source File
# Begin Source File

SOURCE=.\core\http_request.h
# End Source File
# Begin Source File

SOURCE=.\core\httpd.h
# End Source File
# Begin Source File

SOURCE=.\core\md5.h
# End Source File
# Begin Source File

SOURCE=.\modules\standard\mod_mime.h
# End Source File
# Begin Source File

SOURCE=.\core\multithread.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\readdir.h
# End Source File
# Begin Source File

SOURCE=.\regex\regex.h
# End Source File
# Begin Source File

SOURCE=.\core\rfc1413.h
# End Source File
# Begin Source File

SOURCE=.\core\scoreboard.h
# End Source File
# Begin Source File

SOURCE=.\os\win32\service.h
# End Source File
# Begin Source File

SOURCE=.\core\util_date.h
# End Source File
# Begin Source File

SOURCE=.\core\util_md5.h
# End Source File
# Begin Source File

SOURCE=.\core\util_script.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;cnt;rtf;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
