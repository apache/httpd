# Microsoft Developer Studio Project File - Name="Apache" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=Apache - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak" CFG="Apache - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Apache - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "Apache - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Apache - Win32 Release"

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
# ADD CPP /nologo /MD /W3 /Zi /O2 /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /Fd"Release\Apache_src" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /stack:0x40000 /subsystem:console /debug /machine:I386 /opt:ref

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "./include" /I "./srclib/apr/include" /I "./srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /Fd"Debug\Apache_src" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /subsystem:console /incremental:no /debug /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib /nologo /stack:0x40000 /subsystem:console /incremental:no /debug /machine:I386

!ENDIF 

# Begin Target

# Name "Apache - Win32 Release"
# Name "Apache - Win32 Debug"
# Begin Source File

SOURCE=.\build\win32\Apache.ico
# End Source File
# Begin Source File

SOURCE=.\build\win32\Apache.rc
# End Source File
# Begin Source File

SOURCE=.\server\main.c
# End Source File
# Begin Source File

SOURCE=.\build\win32\win32ver.awk

!IF  "$(CFG)" == "Apache - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=.\build\win32\win32ver.awk

".\build\win32\Apache.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ./build/win32/win32ver.awk Apache.exe "Apache HTTP Server"  ./include/ap_release.h icon=apache.ico > .\build\win32\Apache.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=.\build\win32\win32ver.awk

".\build\win32\Apache.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ./build/win32/win32ver.awk Apache.exe "Apache HTTP Server"  ./include/ap_release.h icon=apache.ico > .\build\win32\Apache.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
