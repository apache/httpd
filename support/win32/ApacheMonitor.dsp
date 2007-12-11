# Microsoft Developer Studio Project File - Name="ApacheMonitor" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=ApacheMonitor - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ApacheMonitor.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheMonitor.mak" CFG="ApacheMonitor - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheMonitor - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "ApacheMonitor - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /EHsc /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /FD /c
# ADD CPP /nologo /MD /W3 /EHsc /O2 /Oy- /Zi /I "../../include" /I "../../srclib/apr/include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fd"Release/ApacheMonitor_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /i "../../include" /I "../../srclib/apr/include" /d "NDEBUG" /d "APP_FILE"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows /debug /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\ApacheMonitor.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ELSEIF  "$(CFG)" == "ApacheMonitor - Win32 Debug"

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
# ADD BASE CPP /nologo /W3 /Gm /EHsc /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /FD /c
# ADD CPP /nologo /MDd /W3 /Gm /EHsc /Zi /Od /I "../../include" /I "../../srclib/apr/include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fd"Debug/ApacheMonitor_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /i "../../include" /I "../../srclib/apr/include" /d "_DEBUG" /d "APP_FILE"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows /debug
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows /incremental:no /debug
# Begin Special Build Tool
TargetPath=.\Debug\ApacheMonitor.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "ApacheMonitor - Win32 Release"
# Name "ApacheMonitor - Win32 Debug"
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\apache_header.bmp
# End Source File
# Begin Source File

SOURCE=.\ApacheMonitor.ico
# End Source File
# Begin Source File

SOURCE=.\aprun.ico
# End Source File
# Begin Source File

SOURCE=.\apstop.ico
# End Source File
# Begin Source File

SOURCE=.\srun.bmp
# End Source File
# Begin Source File

SOURCE=.\sstop.bmp
# End Source File
# End Group
# Begin Source File

SOURCE=.\ApacheMonitor.c
# End Source File
# Begin Source File

SOURCE=.\ApacheMonitor.h
# End Source File
# Begin Source File

SOURCE=.\ApacheMonitor.rc
# End Source File
# End Target
# End Project
