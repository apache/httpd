# Microsoft Developer Studio Project File - Name="mod_deflate" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_deflate - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_deflate.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_deflate.mak" CFG="mod_deflate - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_deflate - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_deflate - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_deflate - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "HAVE_ZUTIL_H" /FD /c
# ADD CPP /nologo /MD /W3 /Zi /O2 /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/zlib" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fd"Release\mod_deflate_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /map /machine:I386 /out:"Release/mod_deflate.so" /base:@..\..\os\win32\BaseAddr.ref,mod_deflate.so
# ADD LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /debugtype:both /machine:I386 /out:"Release/mod_deflate.so" /pdbtype:sept /base:@..\..\os\win32\BaseAddr.ref,mod_deflate.so
# Begin Custom Build - Extracting .dbg symbols from $(InputPath)
InputPath=.\Release\mod_deflate.so
SOURCE="$(InputPath)"

".\Release\mod_deflate.dbr" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	rebase -q -i "../../os/win32/BaseAddr.ref" -x ".\Release" $(InputPath)
	echo rebased > ".\Release\mod_deflate.dbr"

# End Custom Build

!ELSEIF  "$(CFG)" == "mod_deflate - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/zlib" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "HAVE_ZUTIL_H" /Fd"Debug\mod_deflate_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /out:"Debug/mod_deflate.so" /base:@..\..\os\win32\BaseAddr.ref,mod_deflate.so
# ADD LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /out:"Debug/mod_deflate.so" /base:@..\..\os\win32\BaseAddr.ref,mod_deflate.so

!ENDIF 

# Begin Target

# Name "mod_deflate - Win32 Release"
# Name "mod_deflate - Win32 Debug"
# Begin Group "zlib"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\srclib\zlib\adler32.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\crc32.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\deflate.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\infblock.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\infcodes.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\inffast.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\inflate.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\inftrees.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\infutil.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\trees.c
# End Source File
# Begin Source File

SOURCE=..\..\srclib\zlib\zutil.c
# End Source File
# End Group
# Begin Source File

SOURCE=.\mod_deflate.c
# End Source File
# Begin Source File

SOURCE=.\mod_deflate.rc
# End Source File
# Begin Source File

SOURCE=..\..\build\win32\win32ver.awk

!IF  "$(CFG)" == "mod_deflate - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\mod_deflate.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk mod_deflate.so "deflate_module for Apache" ../../include/ap_release.h > .\mod_deflate.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "mod_deflate - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\mod_deflate.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk mod_deflate.so "deflate_module for Apache" ../../include/ap_release.h > .\mod_deflate.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
