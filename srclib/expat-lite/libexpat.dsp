# Microsoft Developer Studio Project File - Name="libexpat" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libexpat - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libexpat.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libexpat.mak" CFG="libexpat - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libexpat - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libexpat - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libexpat - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "XMLTOK_EXPORTS" /D "XMLPARSE_EXPORTS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "XML_MIN_SIZE" /D XMLTOKAPI="__declspec(dllexport)" /D XMLPARSEAPI="__declspec(dllexport)" /Fd"Release/libexpat" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /base:"0x6EC00000" /dll /map /machine:I386
# ADD LINK32 /nologo /base:"0x6EC00000" /dll /map /machine:I386

!ELSEIF  "$(CFG)" == "libexpat - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "XMLTOK_EXPORTS" /D "XMLPARSE_EXPORTS" /FD /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "XML_MIN_SIZE" /D XMLTOKAPI="__declspec(dllexport)" /D XMLPARSEAPI="__declspec(dllexport)" /Fd"Debug/libexpat" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /base:"0x6EC00000" /dll /incremental:no /map /debug /machine:I386
# ADD LINK32 /nologo /base:"0x6EC00000" /dll /incremental:no /map /debug /machine:I386

!ENDIF 

# Begin Target

# Name "libexpat - Win32 Release"
# Name "libexpat - Win32 Debug"
# Begin Source File

SOURCE=".\dllmain.c"
# End Source File
# Begin Source File

SOURCE=".\hashtable.c"
# End Source File
# Begin Source File

SOURCE=".\xmlparse.c"
# End Source File
# Begin Source File

SOURCE=".\xmlparse.h"
# End Source File
# Begin Source File

SOURCE=".\xmlrole.c"
# End Source File
# Begin Source File

SOURCE=".\xmltok.c"
# End Source File
# End Target
# End Project
