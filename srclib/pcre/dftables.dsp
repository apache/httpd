# Microsoft Developer Studio Project File - Name="dftables" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=dftables - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "dftables.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "dftables.mak" CFG="dftables - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "dftables - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "dftables - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "dftables - Win32 Release"

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
# ADD CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fd"Release\dftables" /FD /c
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"Release\dftables.pdb" /map /machine:I386
# ADD LINK32 kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"Release\dftables.pdb" /map /machine:I386

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /D "_WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fd"Debug\dftables" /FD /c
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"Debug\dftables.pdb" /map /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"Debug\dftables.pdb" /map /debug /machine:I386

!ENDIF 

# Begin Target

# Name "dftables - Win32 Release"
# Name "dftables - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\dftables.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hw"
# Begin Source File

SOURCE=.\config.hw

!IF  "$(CFG)" == "dftables - Win32 Release"

# Begin Custom Build
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

# Begin Custom Build
InputPath=.\config.hw

".\config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\internal.h
# End Source File
# Begin Source File

SOURCE=.\maketables.c
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\pcre.hw

!IF  "$(CFG)" == "dftables - Win32 Release"

# Begin Custom Build
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

# Begin Custom Build
InputPath=.\pcre.hw

".\pcre.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	
# End Custom Build

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
