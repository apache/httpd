# Microsoft Developer Studio Project File - Name="httpd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=httpd - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "httpd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "httpd.mak" CFG="httpd - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "httpd - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "httpd - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "httpd - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "SHARED_MODULE" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /Fd"Release\httpd" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /i "./include" /i "./srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="httpd.exe" /d LONG_NAME="Apache HTTP Server" /d ICON_FILE="apache.ico"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:console
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /stack:0x40000 /subsystem:console /debug /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\httpd.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ELSEIF  "$(CFG)" == "httpd - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FD /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /Fd"Debug\httpd" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /i "./include" /i "./srclib/apr/include" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="httpd.exe" /d LONG_NAME="Apache HTTP Server" /d ICON_FILE="apache.ico"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:console /incremental:no /debug
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /stack:0x40000 /subsystem:console /incremental:no /debug
# Begin Special Build Tool
TargetPath=.\Debug\httpd.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "httpd - Win32 Release"
# Name "httpd - Win32 Debug"
# Begin Source File

SOURCE=.\build\win32\Apache.ico
# End Source File
# Begin Source File

SOURCE=.\build\win32\httpd.rc
# End Source File
# Begin Source File

SOURCE=.\server\main.c
# End Source File
# End Target
# End Project
