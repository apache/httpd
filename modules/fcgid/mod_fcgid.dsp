# Microsoft Developer Studio Project File - Name="mod_fcgid" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_fcgid - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_fcgid.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_fcgid.mak" CFG="mod_fcgid - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_fcgid - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_fcgid - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_fcgid - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "$(APACHE2_HOME)/include" /Fd"Release\mod_fcgid_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG" /I "../../srclib/apr/include" /I "$(APACHE2_HOME)/include"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /machine:I386 /out:"Release/mod_fcgid.so"
# ADD LINK32 libhttpd.lib libaprutil-1.lib libapr-1.lib kernel32.lib /nologo /subsystem:windows /dll /debug /incremental:no /machine:I386 /out:"Release/mod_fcgid.so" /libpath:"..\..\Release" /libpath:"..\..\srclib\apr\Release" /libpath:"..\..\srclib\apr-util\Release" /libpath:"$(APACHE2_HOME)/lib" /base:"0x46430000" /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\mod_fcgid.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ELSEIF  "$(CFG)" == "mod_fcgid - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Od /Zi /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Od /Zi /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "$(APACHE2_HOME)/include" /Fd"Debug\mod_fcgid_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG" /I "../../srclib/apr/include" /I "$(APACHE2_HOME)/include"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"Debug/mod_fcgid.so"
# ADD LINK32 libhttpd.lib libaprutil-1.lib libapr-1.lib kernel32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /libpath:"..\..\Debug" /libpath:"..\..\srclib\apr\Debug" /libpath:"..\..\srclib\apr-util\Debug" /libpath:"$(APACHE2_HOME)/lib" /out:"Debug/mod_fcgid.so" /base:"0x46430000"
# Begin Special Build Tool
TargetPath=.\Debug\mod_fcgid.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "mod_fcgid - Win32 Release"
# Name "mod_fcgid - Win32 Debug"
# Begin Source File

SOURCE=.\fcgid_bridge.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_bridge.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_bucket.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_bucket.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_conf.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_conf.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_filter.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_filter.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_global.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_pm.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_pm_main.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_pm_main.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_pm_win.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_proc.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_proc_win.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_proctbl.h
# End Source File
# Begin Source File

SOURCE=.\fcgid_proctbl_win.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_protocol.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_spawn_ctl.c
# End Source File
# Begin Source File

SOURCE=.\fcgid_spawn_ctl.h
# End Source File
# Begin Source File

SOURCE=.\mod_fcgid.c
# End Source File
# Begin Source File

SOURCE=.\mod_fcgid.rc
# End Source File
# Begin Source File

SOURCE=.\fcgid_config.h
# End Source File
# Begin Source File

SOURCE=".\fcgid_config.h.in"

!IF  "$(CFG)" == "mod_fcgid - Win32 Release"

# Begin Custom Build - Generating fcgid_config.h
InputPath=".\fcgid_config.h.in"

".\fcgid_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo /* No configuration */ > .\fcgid_config.h

# End Custom Build

!ELSEIF  "$(CFG)" == "mod_fcgid - Win32 Debug"

# Begin Custom Build - Generating fcgid_config.h
InputPath=".\fcgid_config.h.in"

".\fcgid_config.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	echo /* No configuration */ > .\fcgid_config.h

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
