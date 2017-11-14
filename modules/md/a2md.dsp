# Microsoft Developer Studio Project File - Name="a2md" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=a2md - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "a2md.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "a2md.mak" CFG="a2md - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "a2md - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "a2md - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "a2md - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "../../server/mpm/winnt" /I "../../srclib/openssl/inc32" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../core"  /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "ssize_t=long" /Fd"Release\a2md_src" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /fo"Release/a2md.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d "BIN_NAME=a2md.exe" /d "LONG_NAME=a2md command line utility"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib /nologo /subsystem:console
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib libeay32.lib ssleay32.lib jansson.lib libcurl.lib /libpath:"../../Release/" /libpath:"../../srclib/apr/Release" /libpath:"../../srclib/apr-util/Release" /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/curl/lib" /libpath:"../../srclib/jansson/lib" /nologo /subsystem:console /debug /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\a2md.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ELSEIF  "$(CFG)" == "a2md - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /FD /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fd"Debug/a2md_src" /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/a2md.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d "BIN_NAME=a2md.exe" /d "LONG_NAME=a2md command line utility"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib /nologo /subsystem:console /incremental:no /debug
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib libeay32.lib ssleay32.lib jansson_d.lib libcurl.lib /libpath:"../../Debug/" /libpath:"../../srclib/apr/Debug" /libpath:"../../srclib/apr-util/Debug" /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/curl/lib" /libpath:"../../srclib/jansson/lib" /nologo /subsystem:console /debug /opt:ref
# Begin Special Build Tool
TargetPath=.\Debug\a2md.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "a2md - Win32 Release"
# Name "a2md - Win32 Debug"
# Begin Source File

SOURCE=./md_cmd_main.c
# End Source File
# Begin Source File

SOURCE=./md_cmd_acme.c
# End Source File
# Begin Source File

SOURCE=./md_cmd_reg.c
# End Source File
# Begin Source File

SOURCE=./md_cmd_store.c
# End Source File
# Begin Source File

SOURCE=./md_core.c
# End Source File
# Begin Source File

SOURCE=./md_crypt.c
# End Source File
# Begin Source File

SOURCE=./md_curl.c
# End Source File
# Begin Source File

SOURCE=./md_http.c
# End Source File
# Begin Source File

SOURCE=./md_json.c
# End Source File
# Begin Source File

SOURCE=./md_jws.c
# End Source File
# Begin Source File

SOURCE=./md_log.c
# End Source File
# Begin Source File

SOURCE=./md_reg.c
# End Source File
# Begin Source File

SOURCE=./md_store.c
# End Source File
# Begin Source File

SOURCE=./md_store_fs.c
# End Source File
# Begin Source File

SOURCE=./md_util.c
# End Source File
# Begin Source File

SOURCE=./md_acme.c
# End Source File
# Begin Source File

SOURCE=./md_acme_acct.c
# End Source File
# Begin Source File

SOURCE=./md_acme_authz.c
# End Source File
# Begin Source File

SOURCE=./md_acme_drive.c
# End Source File
# Begin Source File


SOURCE=..\..\build\win32\httpd.rc
# End Source File
# End Target
# End Project
