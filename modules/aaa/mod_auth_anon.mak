# Microsoft Developer Studio Generated NMAKE File, Based on mod_auth_anon.dsp
!IF "$(CFG)" == ""
CFG=mod_auth_anon - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_auth_anon - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "mod_auth_anon - Win32 Release" && "$(CFG)" !=\
 "mod_auth_anon - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_auth_anon.mak" CFG="mod_auth_anon - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_auth_anon - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_auth_anon - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "mod_auth_anon - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_anon.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libapr - Win32 Release"\
 "$(OUTDIR)\mod_auth_anon.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_anon.idb"
	-@erase "$(INTDIR)\mod_auth_anon.obj"
	-@erase "$(OUTDIR)\mod_auth_anon.exp"
	-@erase "$(OUTDIR)\mod_auth_anon.lib"
	-@erase "$(OUTDIR)\mod_auth_anon.map"
	-@erase "$(OUTDIR)\mod_auth_anon.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "../../srclib/apr-util/include" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_anon" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_anon.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_auth_anon.pdb" /map:"$(INTDIR)\mod_auth_anon.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_auth_anon.so"\
 /implib:"$(OUTDIR)\mod_auth_anon.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_auth_anon 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_anon.obj" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\mod_auth_anon.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_auth_anon - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_anon.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libapr - Win32 Debug"\
 "$(OUTDIR)\mod_auth_anon.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_anon.idb"
	-@erase "$(INTDIR)\mod_auth_anon.obj"
	-@erase "$(OUTDIR)\mod_auth_anon.exp"
	-@erase "$(OUTDIR)\mod_auth_anon.lib"
	-@erase "$(OUTDIR)\mod_auth_anon.map"
	-@erase "$(OUTDIR)\mod_auth_anon.pdb"
	-@erase "$(OUTDIR)\mod_auth_anon.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "..\..\srclib\apr-util\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_anon" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_anon.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_auth_anon.pdb" /map:"$(INTDIR)\mod_auth_anon.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\mod_auth_anon.so"\
 /implib:"$(OUTDIR)\mod_auth_anon.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_auth_anon 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_anon.obj" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\mod_auth_anon.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

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


!IF "$(CFG)" == "mod_auth_anon - Win32 Release" || "$(CFG)" ==\
 "mod_auth_anon - Win32 Debug"

!IF  "$(CFG)" == "mod_auth_anon - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\aaa"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_auth_anon - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\aaa"

"libapr - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\aaa"

!ENDIF 

!IF  "$(CFG)" == "mod_auth_anon - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\aaa"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_auth_anon - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\aaa"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\aaa"

!ENDIF 

SOURCE=.\mod_auth_anon.c
DEP_CPP_MOD_A=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\os\win32\os.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\srclib\apr-util\include\apu.h"\
	"..\..\srclib\apr\include\apr.h"\
	"..\..\srclib\apr\include\apr_dso.h"\
	"..\..\srclib\apr\include\apr_errno.h"\
	"..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lock.h"\
	"..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\srclib\apr\include\apr_pools.h"\
	"..\..\srclib\apr\include\apr_portable.h"\
	"..\..\srclib\apr\include\apr_sms.h"\
	"..\..\srclib\apr\include\apr_strings.h"\
	"..\..\srclib\apr\include\apr_tables.h"\
	"..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\srclib\apr\include\apr_time.h"\
	"..\..\srclib\apr\include\apr_user.h"\
	"..\..\srclib\apr\include\apr_want.h"\
	
NODEP_CPP_MOD_A=\
	"..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\mod_auth_anon.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"



!ENDIF 

