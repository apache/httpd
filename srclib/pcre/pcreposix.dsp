# Microsoft Developer Studio Project File - Name="pcreposix" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
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
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "pcreposix - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LibR"
# PROP Intermediate_Dir "LibR"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "_WIN32" /D "NDEBUG" /D "_WINDOWS" /D "STATIC" /FD /c
# ADD CPP /nologo /MD /W3 /Zi /O2 /D "_WIN32" /D "NDEBUG" /D "_WINDOWS" /D "STATIC" /Fd"LibR/pcreposix_src" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
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
# PROP Intermediate_Dir "LibD"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "_WIN32" /D "_DEBUG" /D "_WINDOWS" /D "STATIC" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /D "_WIN32" /D "_DEBUG" /D "_WINDOWS" /D "STATIC" /Fd"LibD/pcreposix_src" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
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

# Begin Custom Build - Creating pcre config.h from config.hw 
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\config.hw > .\config.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

# Begin Custom Build - Creating pcre config.h from config.hw 
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\config.hw > .\config.h
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\pcre.hw

!IF  "$(CFG)" == "pcreposix - Win32 Release"

# Begin Custom Build - Creating pcre.h from pcre.hw 
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\pcre.hw > .\pcre.h
	
# End Custom Build

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

# Begin Custom Build - Creating pcre.h from pcre.hw 
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	type .\pcre.hw > .\pcre.h
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\pcreposix.h
# End Source File
# End Group
# End Target
# End Project
