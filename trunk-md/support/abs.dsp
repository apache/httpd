# Microsoft Developer Studio Project File - Name="abs" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=abs - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "abs.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "abs.mak" CFG="abs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "abs - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "abs - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "abs - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "SSL" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fd"Release/abs_src" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /fo"Release/ab.res" /i "../include" /i "../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /libpath:"../srclib/openssl/out32dll"
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /debug /libpath:"../srclib/openssl/out32dll" /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\abs.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "SSL" /FD /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fd"Debug/abs_src" /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/ab.res" /i "../include" /i "../srclib/apr/include" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /incremental:no /debug /libpath:"../srclib/openssl/out32dll"
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib rpcrt4.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /incremental:no /debug /libpath:"../srclib/openssl/out32dll"
# Begin Special Build Tool
TargetPath=.\Debug\abs.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);1
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "abs - Win32 Release"
# Name "abs - Win32 Debug"
# Begin Source File

SOURCE=.\ab.c

!IF  "$(CFG)" == "abs - Win32 Release"

# ADD CPP /Fo"Release/abs.obj"

!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

# ADD CPP /Fo"Debug/abs.obj"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\build\win32\httpd.rc
# End Source File
# End Target
# End Project
