# Microsoft Developer Studio Project File - Name="mod_ssl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=mod_ssl - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "mod_ssl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_ssl.mak" CFG="mod_ssl - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_ssl - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_ssl - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

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
# ADD CPP /nologo /MD /W3 /Zi /O2 /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /D "HAVE_OPENSSL" /D "HAVE_SSL_SET_STATE=1" /Fd"Release\mod_ssl_src" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /machine:I386 /out:"Release/mod_ssl.so" /base:@..\..\os\win32\BaseAddr.ref,mod_ssl.so
# ADD LINK32 kernel32.lib user32.lib wsock32.lib ws2_32.lib advapi32.lib gdi32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"Release/mod_ssl.so" /libpath:"../../srclib/openssl/out32dll" /libpath:"../../srclib/openssl/out32" /base:@..\..\os\win32\BaseAddr.ref,mod_ssl.so /opt:ref

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

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
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /D "HAVE_OPENSSL" /D "HAVE_SSL_SET_STATE=1" /Fd"Debug\mod_ssl_src" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"Debug/mod_ssl.so" /base:@..\..\os\win32\BaseAddr.ref,mod_ssl.so
# ADD LINK32 kernel32.lib user32.lib wsock32.lib ws2_32.lib advapi32.lib gdi32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows /dll /incremental:no /debug /machine:I386 /out:"Debug/mod_ssl.so" /libpath:"../../srclib/openssl/out32dll.dbg" /libpath:"../../srclib/openssl/out32.dbg" /base:@..\..\os\win32\BaseAddr.ref,mod_ssl.so

!ENDIF 

# Begin Target

# Name "mod_ssl - Win32 Release"
# Name "mod_ssl - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "*.c"
# Begin Source File

SOURCE=.\mod_ssl.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_config.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_dh.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_init.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_io.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_kernel.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_log.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_mutex.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_pphrase.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_rand.c
# End Source File
# Begin Source File

SOURCE=.\ssl_engine_vars.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_eval.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_parse.c
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_scan.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache_dbm.c
# End Source File
# Begin Source File

SOURCE=.\ssl_scache_shmcb.c
# End Source File
# Begin Source File

SOURCE=.\ssl_util.c
# End Source File
# Begin Source File

SOURCE=.\ssl_util_ssl.c
# End Source File
# End Group 	 
 # Begin Group "Header Files"

# PROP Default_Filter "*.h"
# Begin Source File

SOURCE=.\mod_ssl.h
# End Source File
# Begin Source File

SOURCE=.\ssl_expr.h
# End Source File
# Begin Source File

SOURCE=.\ssl_expr_parse.h
# End Source File
# Begin Source File

SOURCE=.\ssl_toolkit_compat.h
# End Source File
# Begin Source File

SOURCE=.\ssl_util_ssl.h
# End Source File
# Begin Source File

SOURCE=.\ssl_util_table.h
# End Source File
# End Group
# Begin Group "Generated Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\ssl_expr_parse.y

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

# Begin Custom Build - Generating ssl_expr_parse.c/.h from ssl_expr_parse.y
InputPath=.\ssl_expr_parse.y

BuildCmds= \
	bison -y -d ssl_expr_parse.y \
	sed -e "s;yy;ssl_expr_yy;g" -e  "/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d" <y.tab.c  >ssl_expr_parse.c \
	del y.tab.c \
	sed -e "s;yy;ssl_expr_yy;g" <y.tab.h >ssl_expr_parse.h \
	del y.tab.h \
	

"ssl_expr_parse.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ssl_expr_parse.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

# Begin Custom Build - Generating ssl_expr_parse.c/.h from ssl_expr_parse.y
InputPath=.\ssl_expr_parse.y

BuildCmds= \
	bison -y -d ssl_expr_parse.y \
	sed -e "s;yy;ssl_expr_yy;g" -e  "/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d" <y.tab.c  >ssl_expr_parse.c \
	del y.tab.c \
	sed -e "s;yy;ssl_expr_yy;g" <y.tab.h >ssl_expr_parse.h \
	del y.tab.h \
	

"ssl_expr_parse.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"ssl_expr_parse.h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\ssl_expr_scan.l

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Generating ssl_expr_scan.c from ssl_expr_scan.l
InputPath=.\ssl_expr_scan.l

"ssl_expr_scan.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	flex -Pssl_expr_yy -s -B ssl_expr_scan.l 
	sed -e "/$$Header:/d" <lex.ssl_expr_yy.c >ssl_expr_scan.c 
	del lex.ssl_expr_yy.c 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Generating ssl_expr_scan.c from ssl_expr_scan.l
InputPath=.\ssl_expr_scan.l

"ssl_expr_scan.c" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	flex -Pssl_expr_yy -s -B ssl_expr_scan.l 
	sed -e "/$$Header:/d" <lex.ssl_expr_yy.c >ssl_expr_scan.c 
	del lex.ssl_expr_yy.c 
	
# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Source File

SOURCE=.\mod_ssl.rc
# End Source File
# Begin Source File

SOURCE=..\..\build\win32\win32ver.awk

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\mod_ssl.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk mod_ssl.so "ssl_module for Apache" ../../include/ap_release.h > .\mod_ssl.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\mod_ssl.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk mod_ssl.so "ssl_module for Apache" ../../include/ap_release.h > .\mod_ssl.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
