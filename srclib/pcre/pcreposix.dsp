# Microsoft Developer Studio Project File - Name="pcreposix" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 5.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=pcreposix - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "pcreposix.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "pcreposix.mak" CFG="pcreposix - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "pcreposix - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "pcreposix - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe

!IF  "$(CFG)" == "pcreposix - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LibR"
# PROP Intermediate_Dir "LibR/posix"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LibD"
# PROP Intermediate_Dir "LibD/posix"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "..\include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "pcreposix - Win32 Release"
# Name "pcreposix - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "*.c"
# Begin Source File

SOURCE=.\pcreposix.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "*.h"
# Begin Source File

SOURCE=.\config.hw

!IF  "$(CFG)" == "pcreposix - Win32 Release"

# Begin Custom Build
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo Creating pcre config.h from config.hw 
	copy .\config.hw .\config.h 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

# Begin Custom Build
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo Creating pcre config.h from config.hw 
	copy .\config.hw .\config.h 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\include\pcre.h
# End Source File
# Begin Source File

SOURCE=.\pcre.hw

!IF  "$(CFG)" == "pcreposix - Win32 Release"

# Begin Custom Build
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo Creating pcre.h from pcre.hw 
	copy .\pcre.hw .\pcre.h 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

# Begin Custom Build
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo Creating pcre.h from pcre.hw 
	copy .\pcre.hw .\pcre.h 
	
# End Custom Build

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
