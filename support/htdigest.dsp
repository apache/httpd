# Microsoft Developer Studio Project File - Name="htdigest" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=htdigest - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "htdigest.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "htdigest.mak" CFG="htdigest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "htdigest - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "htdigest - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "htdigest - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /FD /c
# ADD CPP /nologo /MD /W3 /Zi /O2 /I "../srclib/apr/include" /I "../srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fd"Release/htdigest_src" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo /subsystem:console /map /machine:I386
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo /subsystem:console /map /debug /debugtype:both /machine:I386 /pdbtype:sept
# Begin Custom Build - Extracting .dbg symbols from $(InputPath)
InputPath=.\Release\htdigest.so
SOURCE="$(InputPath)"

".\Release\htdigest.dbgmark" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rebase -q -b 0x00400000 -x ".\Release" $(InputPath)
	echo rebased > ".\Release\htdigest.dbgmark"

# End Custom Build

!ELSEIF  "$(CFG)" == "htdigest - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fd"Debug/htdigest_src" /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo /subsystem:console /incremental:no /map /debug /machine:I386
# ADD LINK32 kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo /subsystem:console /incremental:no /map /debug /machine:I386

!ENDIF 

# Begin Target

# Name "htdigest - Win32 Release"
# Name "htdigest - Win32 Debug"
# Begin Source File

SOURCE=.\htdigest.c
# End Source File
# Begin Source File

SOURCE=.\htdigest.rc
# End Source File
# Begin Source File

SOURCE=..\build\win32\win32ver.awk

!IF  "$(CFG)" == "htdigest - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\build\win32\win32ver.awk

".\htdigest.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../build/win32/win32ver.awk htdigest.exe "htdigest Utility"  ../include/ap_release.h > .\htdigest.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "htdigest - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\build\win32\win32ver.awk

".\htdigest.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../build/win32/win32ver.awk htdigest.exe "htdigest Utility"  ../include/ap_release.h > .\htdigest.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
