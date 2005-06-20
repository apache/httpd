# Microsoft Developer Studio Project File - Name="sdbm" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=sdbm - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sdbm.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sdbm.mak" CFG="sdbm - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sdbm - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "sdbm - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "sdbm - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LibR"
# PROP BASE Intermediate_Dir "LibR"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LibR"
# PROP Intermediate_Dir "LibR"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
# ADD BASE CPP /nologo /MD /W3 /O2 /Zi /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "..\..\include" /I "..\..\os\win32" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fd"LibR\sdbm" /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "sdbm - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LibD"
# PROP BASE Intermediate_Dir "LibD"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LibD"
# PROP Intermediate_Dir "LibD"
# PROP Target_Dir ""
RSC=rc.exe
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "SHARED_MODULE" /Fd"LibD\sdbm" /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "sdbm - Win32 Release"
# Name "sdbm - Win32 Debug"
# Begin Source File

SOURCE=.\sdbm.c
# End Source File
# Begin Source File

SOURCE=.\sdbm.h
# End Source File
# Begin Source File

SOURCE=.\sdbm_hash.c
# End Source File
# Begin Source File

SOURCE=.\sdbm_lock.c
# End Source File
# Begin Source File

SOURCE=.\sdbm_pair.c
# End Source File
# Begin Source File

SOURCE=.\sdbm_pair.h
# End Source File
# Begin Source File

SOURCE=.\sdbm_tune.h
# End Source File
# End Target
# End Project
