# Microsoft Developer Studio Generated NMAKE File, Based on mod_proxy.dsp
!IF "$(CFG)" == ""
CFG=mod_proxy - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_proxy - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_proxy - Win32 Release" && "$(CFG)" !=\
 "mod_proxy - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_proxy.mak" CFG="mod_proxy - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_proxy - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_proxy - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_proxy - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_proxy.so"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\mod_proxy.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_proxy.idb"
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(OUTDIR)\mod_proxy.exp"
	-@erase "$(OUTDIR)\mod_proxy.lib"
	-@erase "$(OUTDIR)\mod_proxy.map"
	-@erase "$(OUTDIR)\mod_proxy.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\modules\proxy" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE"\
 /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_proxy" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_proxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\mod_proxy.pdb" /map:"$(INTDIR)\mod_proxy.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_proxy.so" /implib:"$(OUTDIR)\mod_proxy.lib"\
 /base:@"BaseAddr.ref",mod_proxy 
LINK32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj" \
	"..\..\Release\ApacheCore.lib"

"$(OUTDIR)\mod_proxy.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_proxy - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_proxy.so"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\mod_proxy.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_proxy.idb"
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(OUTDIR)\mod_proxy.exp"
	-@erase "$(OUTDIR)\mod_proxy.lib"
	-@erase "$(OUTDIR)\mod_proxy.map"
	-@erase "$(OUTDIR)\mod_proxy.pdb"
	-@erase "$(OUTDIR)\mod_proxy.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\modules\proxy" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE"\
 /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_proxy" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_proxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\mod_proxy.pdb" /map:"$(INTDIR)\mod_proxy.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\mod_proxy.so"\
 /implib:"$(OUTDIR)\mod_proxy.lib" /base:@"BaseAddr.ref",mod_proxy 
LINK32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj" \
	"..\..\Debug\ApacheCore.lib"

"$(OUTDIR)\mod_proxy.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "mod_proxy - Win32 Release" || "$(CFG)" ==\
 "mod_proxy - Win32 Debug"
SOURCE=..\..\modules\proxy\mod_proxy.c
DEP_CPP_MOD_P=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\http_vhost.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_MOD_P=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\modules\proxy\proxy_cache.c
DEP_CPP_PROXY=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_md5.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_conf_globals.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\multithread.h"\
	"..\..\include\util_date.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_PROXY=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\modules\proxy\proxy_connect.c
DEP_CPP_PROXY_=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_PROXY_=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\proxy_connect.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\modules\proxy\proxy_ftp.c
DEP_CPP_PROXY_F=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_PROXY_F=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\modules\proxy\proxy_http.c
DEP_CPP_PROXY_H=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_date.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_PROXY_H=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\..\modules\proxy\proxy_util.c
DEP_CPP_PROXY_U=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_ebcdic.h"\
	"..\..\include\ap_md5.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\explain.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\multithread.h"\
	"..\..\include\util_date.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\proxy\mod_proxy.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_PROXY_U=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\proxy_util.obj" : $(SOURCE) $(DEP_CPP_PROXY_U) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!IF  "$(CFG)" == "mod_proxy - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "mod_proxy - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Debug" RECURSE=1 
   cd ".\os\win32"

!ENDIF 


!ENDIF 

