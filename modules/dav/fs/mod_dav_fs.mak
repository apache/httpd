# Microsoft Developer Studio Generated NMAKE File, Based on mod_dav_fs.dsp
!IF "$(CFG)" == ""
CFG=mod_dav_fs - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_dav_fs - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_dav_fs - Win32 Release" && "$(CFG)" !=\
 "mod_dav_fs - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_dav_fs.mak" CFG="mod_dav_fs - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_dav_fs - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_dav_fs - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav_fs.so"

!ELSE 

ALL : "mod_dav - Win32 Release" "libhttpd - Win32 Release"\
 "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_dav_fs.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" "mod_dav - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dbm.obj"
	-@erase "$(INTDIR)\lock.obj"
	-@erase "$(INTDIR)\mod_dav_fs.idb"
	-@erase "$(INTDIR)\mod_dav_fs.obj"
	-@erase "$(INTDIR)\repos.obj"
	-@erase "$(OUTDIR)\mod_dav_fs.exp"
	-@erase "$(OUTDIR)\mod_dav_fs.lib"
	-@erase "$(OUTDIR)\mod_dav_fs.map"
	-@erase "$(OUTDIR)\mod_dav_fs.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\main" /I "..\..\..\srclib\aputil" /I\
 "..\..\..\srclib\sdbm" /I "..\..\..\srclib\expat-lite" /I\
 "..\..\..\srclib\apr\include" /I "../../../srclib/apr-util/include" /I\
 "..\..\..\include" /I "..\..\..\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav_fs" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav_fs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_dav_fs.pdb"\
 /map:"$(INTDIR)\mod_dav_fs.map" /machine:I386 /out:"$(OUTDIR)\mod_dav_fs.so"\
 /implib:"$(OUTDIR)\mod_dav_fs.lib"\
 /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav_fs 
LINK32_OBJS= \
	"$(INTDIR)\dbm.obj" \
	"$(INTDIR)\lock.obj" \
	"$(INTDIR)\mod_dav_fs.obj" \
	"$(INTDIR)\repos.obj" \
	"..\..\..\Release\libhttpd.lib" \
	"..\..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\..\srclib\apr\Release\libapr.lib" \
	"..\main\Release\mod_dav.lib"

"$(OUTDIR)\mod_dav_fs.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav_fs.so"

!ELSE 

ALL : "mod_dav - Win32 Debug" "libhttpd - Win32 Debug"\
 "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_dav_fs.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" "mod_dav - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dbm.obj"
	-@erase "$(INTDIR)\lock.obj"
	-@erase "$(INTDIR)\mod_dav_fs.idb"
	-@erase "$(INTDIR)\mod_dav_fs.obj"
	-@erase "$(INTDIR)\repos.obj"
	-@erase "$(OUTDIR)\mod_dav_fs.exp"
	-@erase "$(OUTDIR)\mod_dav_fs.lib"
	-@erase "$(OUTDIR)\mod_dav_fs.map"
	-@erase "$(OUTDIR)\mod_dav_fs.pdb"
	-@erase "$(OUTDIR)\mod_dav_fs.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\main" /I "..\..\..\srclib\aputil"\
 /I "..\..\..\srclib\sdbm" /I "..\..\..\srclib\expat-lite" /I\
 "..\..\..\srclib\apr\include" /I "../../../srclib/apr-util/include" /I\
 "..\..\..\include" /I "..\..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav_fs" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav_fs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_dav_fs.pdb"\
 /map:"$(INTDIR)\mod_dav_fs.map" /debug /machine:I386\
 /out:"$(OUTDIR)\mod_dav_fs.so" /implib:"$(OUTDIR)\mod_dav_fs.lib"\
 /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav_fs 
LINK32_OBJS= \
	"$(INTDIR)\dbm.obj" \
	"$(INTDIR)\lock.obj" \
	"$(INTDIR)\mod_dav_fs.obj" \
	"$(INTDIR)\repos.obj" \
	"..\..\..\Debug\libhttpd.lib" \
	"..\..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\..\srclib\apr\Debug\libapr.lib" \
	"..\main\Debug\mod_dav.lib"

"$(OUTDIR)\mod_dav_fs.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "mod_dav_fs - Win32 Release" || "$(CFG)" ==\
 "mod_dav_fs - Win32 Debug"
SOURCE=.\dbm.c
DEP_CPP_DBM_C=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\httpd.h"\
	"..\..\..\include\pcreposix.h"\
	"..\..\..\include\util_filter.h"\
	"..\..\..\include\util_xml.h"\
	"..\..\..\os\win32\os.h"\
	"..\..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\..\srclib\apr-util\include\apr_dbm.h"\
	"..\..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\..\srclib\apr-util\include\apr_xml.h"\
	"..\..\..\srclib\apr-util\include\apu.h"\
	"..\..\..\srclib\apr-util\include\apu_compat.h"\
	"..\..\..\srclib\apr\include\apr.h"\
	"..\..\..\srclib\apr\include\apr_compat.h"\
	"..\..\..\srclib\apr\include\apr_errno.h"\
	"..\..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\..\srclib\apr\include\apr_general.h"\
	"..\..\..\srclib\apr\include\apr_hash.h"\
	"..\..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\..\srclib\apr\include\apr_pools.h"\
	"..\..\..\srclib\apr\include\apr_sms.h"\
	"..\..\..\srclib\apr\include\apr_strings.h"\
	"..\..\..\srclib\apr\include\apr_tables.h"\
	"..\..\..\srclib\apr\include\apr_time.h"\
	"..\..\..\srclib\apr\include\apr_user.h"\
	"..\..\..\srclib\apr\include\apr_want.h"\
	"..\main\mod_dav.h"\
	".\repos.h"\
	
NODEP_CPP_DBM_C=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\dbm.obj" : $(SOURCE) $(DEP_CPP_DBM_C) "$(INTDIR)"


SOURCE=.\lock.c
DEP_CPP_LOCK_=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_log.h"\
	"..\..\..\include\httpd.h"\
	"..\..\..\include\pcreposix.h"\
	"..\..\..\include\util_filter.h"\
	"..\..\..\include\util_xml.h"\
	"..\..\..\os\win32\os.h"\
	"..\..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\..\srclib\apr-util\include\apr_dbm.h"\
	"..\..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\..\srclib\apr-util\include\apr_xml.h"\
	"..\..\..\srclib\apr-util\include\apu.h"\
	"..\..\..\srclib\apr-util\include\apu_compat.h"\
	"..\..\..\srclib\apr\include\apr.h"\
	"..\..\..\srclib\apr\include\apr_compat.h"\
	"..\..\..\srclib\apr\include\apr_errno.h"\
	"..\..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\..\srclib\apr\include\apr_general.h"\
	"..\..\..\srclib\apr\include\apr_hash.h"\
	"..\..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\..\srclib\apr\include\apr_pools.h"\
	"..\..\..\srclib\apr\include\apr_sms.h"\
	"..\..\..\srclib\apr\include\apr_strings.h"\
	"..\..\..\srclib\apr\include\apr_tables.h"\
	"..\..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\..\srclib\apr\include\apr_time.h"\
	"..\..\..\srclib\apr\include\apr_user.h"\
	"..\..\..\srclib\apr\include\apr_uuid.h"\
	"..\..\..\srclib\apr\include\apr_want.h"\
	"..\main\mod_dav.h"\
	".\repos.h"\
	
NODEP_CPP_LOCK_=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\lock.obj" : $(SOURCE) $(DEP_CPP_LOCK_) "$(INTDIR)"


SOURCE=.\mod_dav_fs.c
DEP_CPP_MOD_D=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_config.h"\
	"..\..\..\include\httpd.h"\
	"..\..\..\include\pcreposix.h"\
	"..\..\..\include\util_cfgtree.h"\
	"..\..\..\include\util_filter.h"\
	"..\..\..\include\util_xml.h"\
	"..\..\..\os\win32\os.h"\
	"..\..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\..\srclib\apr-util\include\apr_dbm.h"\
	"..\..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\..\srclib\apr-util\include\apr_xml.h"\
	"..\..\..\srclib\apr-util\include\apu.h"\
	"..\..\..\srclib\apr-util\include\apu_compat.h"\
	"..\..\..\srclib\apr\include\apr.h"\
	"..\..\..\srclib\apr\include\apr_compat.h"\
	"..\..\..\srclib\apr\include\apr_errno.h"\
	"..\..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\..\srclib\apr\include\apr_general.h"\
	"..\..\..\srclib\apr\include\apr_hash.h"\
	"..\..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\..\srclib\apr\include\apr_pools.h"\
	"..\..\..\srclib\apr\include\apr_sms.h"\
	"..\..\..\srclib\apr\include\apr_tables.h"\
	"..\..\..\srclib\apr\include\apr_time.h"\
	"..\..\..\srclib\apr\include\apr_user.h"\
	"..\..\..\srclib\apr\include\apr_want.h"\
	"..\main\mod_dav.h"\
	".\repos.h"\
	
NODEP_CPP_MOD_D=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\mod_dav_fs.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


SOURCE=.\repos.c
DEP_CPP_REPOS=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_log.h"\
	"..\..\..\include\http_protocol.h"\
	"..\..\..\include\http_request.h"\
	"..\..\..\include\httpd.h"\
	"..\..\..\include\pcreposix.h"\
	"..\..\..\include\util_filter.h"\
	"..\..\..\include\util_xml.h"\
	"..\..\..\os\win32\os.h"\
	"..\..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\..\srclib\apr-util\include\apr_dbm.h"\
	"..\..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\..\srclib\apr-util\include\apr_xml.h"\
	"..\..\..\srclib\apr-util\include\apu.h"\
	"..\..\..\srclib\apr-util\include\apu_compat.h"\
	"..\..\..\srclib\apr\include\apr.h"\
	"..\..\..\srclib\apr\include\apr_compat.h"\
	"..\..\..\srclib\apr\include\apr_dso.h"\
	"..\..\..\srclib\apr\include\apr_errno.h"\
	"..\..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\..\srclib\apr\include\apr_general.h"\
	"..\..\..\srclib\apr\include\apr_hash.h"\
	"..\..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\..\srclib\apr\include\apr_lock.h"\
	"..\..\..\srclib\apr\include\apr_mmap.h"\
	"..\..\..\srclib\apr\include\apr_network_io.h"\
	"..\..\..\srclib\apr\include\apr_pools.h"\
	"..\..\..\srclib\apr\include\apr_portable.h"\
	"..\..\..\srclib\apr\include\apr_sms.h"\
	"..\..\..\srclib\apr\include\apr_strings.h"\
	"..\..\..\srclib\apr\include\apr_tables.h"\
	"..\..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\..\srclib\apr\include\apr_time.h"\
	"..\..\..\srclib\apr\include\apr_user.h"\
	"..\..\..\srclib\apr\include\apr_want.h"\
	"..\main\mod_dav.h"\
	".\repos.h"\
	
NODEP_CPP_REPOS=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\repos.obj" : $(SOURCE) $(DEP_CPP_REPOS) "$(INTDIR)"


!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\dav\fs"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\dav\fs"

"libapr - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\dav\fs"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\dav\fs"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\dav\fs"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\dav\fs"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"mod_dav - Win32 Release" : 
   cd "..\../../..\httpd-2.0\modules\dav\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Release" 
   cd "..\fs"

"mod_dav - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0\modules\dav\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\mod_dav.mak" CFG="mod_dav - Win32 Release"\
 RECURSE=1 
   cd "..\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"mod_dav - Win32 Debug" : 
   cd "..\../../..\httpd-2.0\modules\dav\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Debug" 
   cd "..\fs"

"mod_dav - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0\modules\dav\main"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\mod_dav.mak" CFG="mod_dav - Win32 Debug"\
 RECURSE=1 
   cd "..\fs"

!ENDIF 


!ENDIF 

