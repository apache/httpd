# Microsoft Developer Studio Project File - Name="mod_tls" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_tls - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_tls.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_tls.mak" CFG="mod_tls - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_tls - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_tls - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_tls - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /I "../../include" /I "../../os/win32" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fd"Release\mod_tls" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /out:"Release/mod_tls.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_tls
# ADD LINK32 kernel32.lib ssleay32.lib libeay32.lib /nologo /libpath:"../../srclib/openssl/out32dll" /subsystem:windows /dll /incremental:no /map /out:"Release/mod_tls.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_tls

!ELSEIF  "$(CFG)" == "mod_tls - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /I "../../include" /I "../../os/win32" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fd"Debug\mod_tls" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /out:"Debug/mod_tls.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_tls
# ADD LINK32 kernel32.lib ssleay32.lib libeay32.lib /nologo /libpath:"../../srclib/openssl/out32dll.dbg" /subsystem:windows /dll /incremental:no /map /debug /out:"Debug/mod_tls.so" /machine:I386 /base:@..\..\os\win32\BaseAddr.ref,mod_tls

!ENDIF 

# Begin Target

# Name "mod_tls - Win32 Release"
# Name "mod_tls - Win32 Debug"
# Begin Source File

SOURCE=.\mod_tls.c
# End Source File
# Begin Source File

SOURCE=.\openssl_state_machine.c
# End Source File
# Begin Source File

SOURCE=.\openssl_state_machine.h
# End Source File
# End Target
# End Project
