# Microsoft Developer Studio Generated NMAKE File, Based on mod_auth_digest.dsp
!IF "$(CFG)" == ""
CFG=mod_auth_digest - Win32 Debug
!MESSAGE No configuration specified. Defaulting to mod_auth_digest - Win32\
 Debug.
!ENDIF 

!IF "$(CFG)" != "mod_auth_digest - Win32 Release" && "$(CFG)" !=\
 "mod_auth_digest - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_auth_digest.mak" CFG="mod_auth_digest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_auth_digest - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_auth_digest - Win32 Debug" (based on\
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

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_digest.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\mod_auth_digest.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_digest.idb"
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(OUTDIR)\mod_auth_digest.exp"
	-@erase "$(OUTDIR)\mod_auth_digest.lib"
	-@erase "$(OUTDIR)\mod_auth_digest.map"
	-@erase "$(OUTDIR)\mod_auth_digest.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "../../srclib/apr-util/include" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_digest" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_digest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_auth_digest.pdb" /map:"$(INTDIR)\mod_auth_digest.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_auth_digest.so"\
 /implib:"$(OUTDIR)\mod_auth_digest.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_auth_digest 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\mod_auth_digest.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_digest.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\mod_auth_digest.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_digest.idb"
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(OUTDIR)\mod_auth_digest.exp"
	-@erase "$(OUTDIR)\mod_auth_digest.lib"
	-@erase "$(OUTDIR)\mod_auth_digest.map"
	-@erase "$(OUTDIR)\mod_auth_digest.pdb"
	-@erase "$(OUTDIR)\mod_auth_digest.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /I\
 "..\..\srclib\apr\include" /I "../../srclib/apr-util/include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_digest" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_digest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\mod_auth_digest.pdb" /map:"$(INTDIR)\mod_auth_digest.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\mod_auth_digest.so"\
 /implib:"$(OUTDIR)\mod_auth_digest.lib"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_auth_digest 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\mod_auth_digest.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "mod_auth_digest - Win32 Release" || "$(CFG)" ==\
 "mod_auth_digest - Win32 Debug"

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\aaa"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

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

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\aaa"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\aaa"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\aaa"

!ENDIF 

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\aaa"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

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

SOURCE=.\mod_auth_digest.c
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
	"..\..\include\util_md5.h"\
	"..\..\os\win32\os.h"\
	"..\..\srclib\apr-util\include\apr_base64.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\srclib\apr-util\include\apr_sha1.h"\
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
	"..\..\srclib\apr\include\apr_lib.h"\
	"..\..\srclib\apr\include\apr_lock.h"\
	"..\..\srclib\apr\include\apr_md5.h"\
	"..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\srclib\apr\include\apr_pools.h"\
	"..\..\srclib\apr\include\apr_portable.h"\
	"..\..\srclib\apr\include\apr_shmem.h"\
	"..\..\srclib\apr\include\apr_sms.h"\
	"..\..\srclib\apr\include\apr_strings.h"\
	"..\..\srclib\apr\include\apr_tables.h"\
	"..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\srclib\apr\include\apr_time.h"\
	"..\..\srclib\apr\include\apr_user.h"\
	"..\..\srclib\apr\include\apr_want.h"\
	"..\..\srclib\apr\include\apr_xlate.h"\
	
NODEP_CPP_MOD_A=\
	"..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\mod_auth_digest.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"



!ENDIF 

