# Microsoft Developer Studio Project File - Name="htpasswd" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=htpasswd - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "htpasswd.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "htpasswd.mak" CFG="htpasswd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "htpasswd - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "htpasswd - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "htpasswd - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /Oy- /Zi /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Zi /I "..\include" /I "..\os\win32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fd"Release\htpasswd_src" /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /opt:ref
# ADD LINK32 ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386 /opt:ref

!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fd"Debug\htpasswd_src" /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386
# ADD LINK32 ws2_32.lib /nologo /subsystem:console /incremental:no /debug /machine:I386

!ENDIF 

# Begin Target

# Name "htpasswd - Win32 Release"
# Name "htpasswd - Win32 Debug"
# Begin Source File

SOURCE=..\ap\ap_base64.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_checkpass.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_cpystrn.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_getpass.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_md5c.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_sha1.c
# End Source File
# Begin Source File

SOURCE=..\ap\ap_snprintf.c
# End Source File
# Begin Source File

SOURCE=.\htpasswd.c
# End Source File
# End Target
# End Project
