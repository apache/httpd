# Microsoft Developer Studio Project File - Name="libapreq" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libapreq - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libapreq.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libapreq.mak" CFG="libapreq - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libapreq - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libapreq - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libapreq - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /D "APREQ_DECLARE_EXPORT" /FD /c
# ADD CPP /nologo /MD /W3 /Zi /O2 /Oy- /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /I "./srclib/pcre" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /D "APREQ_DECLARE_EXPORT" /Fd"Release\libapreq_cl" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /fo"Release/libapreq.res" /i "./include" /i "./srclib/apr/include" /d "NDEBUG" /d BIN_NAME="libapreq.dll" /d LONG_NAME="libapreq"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /machine:IX86
# ADD LINK32 pcre.lib kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /debug /machine:IX86 /libpath:"./srclib/pcre" /base:@"os\win32\BaseAddr.ref",libapreq.dll /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\libapreq.dll
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ELSEIF  "$(CFG)" == "libapreq - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS"/D "AP_DECLARE_EXPORT" /D "APREQ_DECLARE_EXPORT"  /FD /EHsc /c
# ADD CPP /nologo /MDd /W3 /Zi /Od /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /I "./srclib/pcre" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT" /D "APREQ_DECLARE_EXPORT" /Fd"Debug\libapreq_cl" /FD /EHsc /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/libapreq.res" /i "./include" /i "./srclib/apr/include" /d "_DEBUG" /d BIN_NAME="libapreq.dll" /d LONG_NAME="libapreq"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:IX86
# ADD LINK32 pcred.lib kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:IX86 /libpath:"./srclib/pcre" /base:@"os\win32\BaseAddr.ref",libapreq.dll
# Begin Special Build Tool
TargetPath=.\Debug\libapreq.dll
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "libapreq - Win32 Release"
# Name "libapreq - Win32 Debug"
# Begin Group "headers"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;hpj;bat;for;f90"
# Begin Source File

SOURCE=.\include\ap_config.h
# End Source File
# Begin Source File

SOURCE=.\include\ap_release.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_cookie.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_error.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_module.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_param.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_parser.h
# End Source File
# Begin Source File

SOURCE=.\include\apreq_util.h
# End Source File
# End Group
# Begin Group "libapreq"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\server\apreq_cookie.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_error.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_module.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_module_cgi.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_module_custom.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_param.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_parser.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_parser_header.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_parser_multipart.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_parser_urlencoded.c
# End Source File
# Begin Source File

SOURCE=.\server\apreq_util.c
# End Source File
# Begin Source File

SOURCE=.\server\buildmark.c
# PROP Exclude_From_Build 1
# End Source File
# End Group
# Begin Source File

SOURCE=.\build\win32\httpd.rc
# End Source File
# End Target
# End Project
