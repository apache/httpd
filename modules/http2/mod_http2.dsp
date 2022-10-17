# Microsoft Developer Studio Project File - Name="mod_http2" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_http2 - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_http2.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_http2.mak" CFG="mod_http2 - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_http2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_http2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_http2 - Win32 Release"

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
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "ssize_t=long" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "../ssl" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/nghttp2/lib/includes" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "ssize_t=long" /Fd"Release\mod_http2_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /fo"Release/mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib nghttp2.lib /nologo /subsystem:windows /dll /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /out:".\Release\mod_http2.so" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so
# ADD LINK32 kernel32.lib nghttp2.lib /nologo /subsystem:windows /dll /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /incremental:no /debug /out:".\Release\mod_http2.so" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\mod_http2.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"

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
# ADD BASE CPP /nologo /MDd /W3 /EHsc /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "ssize_t=long" /FD /c
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "../ssl" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/nghttp2/lib/includes" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "ssize_t=long" /Fd"Debug\mod_http2_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib nghttp2d.lib /nologo /subsystem:windows /dll /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /incremental:no /debug /out:".\Debug\mod_http2.so" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so
# ADD LINK32 kernel32.lib nghttp2d.lib /nologo /subsystem:windows /dll /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /incremental:no /debug /out:".\Debug\mod_http2.so" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so
# Begin Special Build Tool
TargetPath=.\Debug\mod_http2.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "mod_http2 - Win32 Release"
# Name "mod_http2 - Win32 Debug"
# Begin Source File

SOURCE=./h2_bucket_beam.c
# End Source File
# Begin Source File

SOURCE=./h2_bucket_eos.c
# End Source File
# Begin Source File

SOURCE=./h2_c1.c
# End Source File
# Begin Source File

SOURCE=./h2_c1_io.c
# End Source File
# Begin Source File

SOURCE=./h2_c2.c
# End Source File
# Begin Source File

SOURCE=./h2_c2_filter.c
# End Source File
# Begin Source File

SOURCE=./h2_config.c
# End Source File
# Begin Source File

SOURCE=./h2_conn_ctx.c
# End Source File
# Begin Source File

SOURCE=./h2_headers.c
# End Source File
# Begin Source File

SOURCE=./h2_mplx.c
# End Source File
# Begin Source File

SOURCE=./h2_protocol.c
# End Source File
# Begin Source File

SOURCE=./h2_push.c
# End Source File
# Begin Source File

SOURCE=./h2_request.c
# End Source File
# Begin Source File

SOURCE=./h2_session.c
# End Source File
# Begin Source File

SOURCE=./h2_stream.c
# End Source File
# Begin Source File

SOURCE=./h2_switch.c
# End Source File
# Begin Source File

SOURCE=./h2_util.c
# End Source File
# Begin Source File

SOURCE=./h2_workers.c
# End Source File
# Begin Source File

SOURCE=./mod_http2.c
# End Source File
# Begin Source File

SOURCE=./mod_http2.c
# End Source File
# Begin Source File

SOURCE=..\..\build\win32\httpd.rc
# End Source File
# End Target
# End Project
