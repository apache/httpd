# Microsoft Developer Studio Project File - Name="gen_uri_delims" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=gen_uri_delims - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "gen_uri_delims.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_uri_delims - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "gen_uri_delims - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gen_uri_delims - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fd"Release\gen_uri_delims" /FD /c
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:console /incremental:no /pdb:"Debug\gen_uri_delims.pdb" /machine:I386
# ADD LINK32 /nologo /subsystem:console /incremental:no /pdb:"Release\gen_uri_delims.pdb" /machine:I386
# Begin Special Build Tool
SOURCE=$(InputPath)
PostBuild_Desc=Create uri_delims.h
PostBuild_Cmds=.\gen_uri_delims > uri_delims.h
# End Special Build Tool

!ELSEIF  "$(CFG)" == "gen_uri_delims - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fd"Debug\gen_uri_delims" /FD /c
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:console /incremental:no /pdb:"Debug\gen_uri_delims.pdb" /debug /machine:I386
# ADD LINK32 /nologo /subsystem:console /incremental:no /pdb:"Debug\gen_uri_delims.pdb" /debug /machine:I386
# Begin Special Build Tool
SOURCE=$(InputPath)
PostBuild_Desc=Create uri_delims.h
PostBuild_Cmds=.\gen_uri_delims > uri_delims.h
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "gen_uri_delims - Win32 Release"
# Name "gen_uri_delims - Win32 Debug"
# Begin Source File

SOURCE=.\gen_uri_delims.c
# End Source File
# End Target
# End Project
