# Microsoft Developer Studio Project File - Name="mod_md" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_md - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_md.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_md.mak" CFG="mod_md - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_md - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_md - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_md - Win32 Release"

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
# ADD CPP /nologo /MD /W3 /O2 /Oy- /Zi /I "../../server/mpm/winnt" "/I ../ssl" /I "../../include" /I "../generators" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../core"   /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "ssize_t=long" /Fd"Release\mod_md_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /fo"Release/mod_md.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d "BIN_NAME=mod_md.so" /d "LONG_NAME=Letsencrypt module for Apache"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /out:".\Release\mod_md.so" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so
# ADD LINK32 kernel32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib ssleay32.lib libeay32.lib jansson.lib libcurl.lib /libpath:"../../srclib/apr/Release" /libpath:"../../srclib/apr-util/Release" /libpath:"../../Release/" /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/jansson/lib" /libpath:"../../srclib/curl/lib" /nologo /subsystem:windows /dll /incremental:no /debug /out:".\Release\mod_md.so" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so /opt:ref
# Begin Special Build Tool
TargetPath=.\Release\mod_md.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"

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
# ADD CPP /nologo /MDd /W3 /EHsc /Zi /Od /I "../ssl" /I "../../include" /I "../../srclib/apr/include" /I "../generators" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../core" /src" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "ssize_t=long" /Fd"Debug\mod_md_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/mod_md.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d "BIN_NAME=mod_md.so" /d "LONG_NAME=md_module for Apache"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /debug /out:".\Debug\mod_md.so" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so
# ADD LINK32 kernel32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib ssleay32.lib libeay32.lib jansson_d.lib libcurl_debug.lib /nologo /subsystem:windows /dll /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/jansson/lib" /libpath:"../../srclib/curl/lib" /incremental:no /debug /out:".\Debug\mod_md.so" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so
# Begin Special Build Tool
TargetPath=.\Debug\mod_md.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
PostBuild_Cmds=if exist $(TargetPath).manifest mt.exe -manifest $(TargetPath).manifest -outputresource:$(TargetPath);2
# End Special Build Tool

!ENDIF 

# Begin Target

# Name "mod_md - Win32 Release"
# Name "mod_md - Win32 Debug"
# Begin Source File

SOURCE=./mod_md.c
# End Source File
# Begin Source File

SOURCE=./mod_md_config.c
# End Source File
# Begin Source File

SOURCE=./mod_md_drive.c
# End Source File
# Begin Source File

SOURCE=./mod_md_ocsp.c
# End Source File
# Begin Source File

SOURCE=./mod_md_os.c
# End Source File
# Begin Source File

SOURCE=./mod_md_status.c
# End Source File
# Begin Source File

SOURCE=./md_acme.c
# End Source File
# Begin Source File

SOURCE=./md_acme_acct.c
# End Source File
# Begin Source File

SOURCE=./md_acme_authz.c
# End Source File
# Begin Source File

SOURCE=./md_acme_drive.c
# End Source File
# Begin Source File

SOURCE=./md_acme_order.c
# End Source File
# Begin Source File

SOURCE=./md_acmev2_drive.c
# End Source File
# Begin Source File

SOURCE=./md_core.c
# End Source File
# Begin Source File

SOURCE=./md_crypt.c
# End Source File
# Begin Source File

SOURCE=./md_curl.c
# End Source File
# Begin Source File

SOURCE=./md_http.c
# End Source File
# Begin Source File

SOURCE=./md_event.c
# End Source File
# Begin Source File

SOURCE=./md_json.c
# End Source File
# Begin Source File

SOURCE=./md_jws.c
# End Source File
# Begin Source File

SOURCE=./md_log.c
# End Source File
# Begin Source File

SOURCE=./md_ocsp.c
# End Source File
# Begin Source File

SOURCE=./md_reg.c
# End Source File
# Begin Source File

SOURCE=./md_result.c
# End Source File
# Begin Source File

SOURCE=./md_status.c
# End Source File
# Begin Source File

SOURCE=./md_store.c
# End Source File
# Begin Source File

SOURCE=./md_store_fs.c
# End Source File
# Begin Source File

SOURCE=./md_tailscale.c
# End Source File
# Begin Source File

SOURCE=./md_time.c
# End Source File
# Begin Source File

SOURCE=./md_util.c
# End Source File
# Begin Source File

SOURCE=..\..\build\win32\httpd.rc
# End Source File
# End Target
# End Project
