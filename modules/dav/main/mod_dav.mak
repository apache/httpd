# Microsoft Developer Studio Generated NMAKE File, Based on mod_dav.dsp
!IF "$(CFG)" == ""
CFG=mod_dav - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_dav - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_dav - Win32 Release" && "$(CFG)" !=\
 "mod_dav - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_dav.mak" CFG="mod_dav - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_dav - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_dav - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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

!IF  "$(CFG)" == "mod_dav - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\mod_dav.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\liveprop.obj"
	-@erase "$(INTDIR)\mod_dav.idb"
	-@erase "$(INTDIR)\mod_dav.obj"
	-@erase "$(INTDIR)\props.obj"
	-@erase "$(INTDIR)\providers.obj"
	-@erase "$(INTDIR)\std_liveprop.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_lock.obj"
	-@erase "$(OUTDIR)\mod_dav.exp"
	-@erase "$(OUTDIR)\mod_dav.lib"
	-@erase "$(OUTDIR)\mod_dav.map"
	-@erase "$(OUTDIR)\mod_dav.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\..\srclib\aputil" /I\
 "..\..\..\srclib\sdbm" /I "..\..\..\srclib\expat-lite" /I\
 "..\..\..\srclib\apr\include" /I "../../../srclib/apr-util/include" /I\
 "..\..\..\include" /I "..\..\..\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS"\
 /D "DAV_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_dav.pdb" /map:"$(INTDIR)\mod_dav.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_dav.so" /implib:"$(OUTDIR)\mod_dav.lib"\
 /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav 
LINK32_OBJS= \
	"$(INTDIR)\liveprop.obj" \
	"$(INTDIR)\mod_dav.obj" \
	"$(INTDIR)\props.obj" \
	"$(INTDIR)\providers.obj" \
	"$(INTDIR)\std_liveprop.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_lock.obj" \
	"..\..\..\Release\libhttpd.lib" \
	"..\..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\..\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\mod_dav.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_dav - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\mod_dav.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\liveprop.obj"
	-@erase "$(INTDIR)\mod_dav.idb"
	-@erase "$(INTDIR)\mod_dav.obj"
	-@erase "$(INTDIR)\props.obj"
	-@erase "$(INTDIR)\providers.obj"
	-@erase "$(INTDIR)\std_liveprop.obj"
	-@erase "$(INTDIR)\util.obj"
	-@erase "$(INTDIR)\util_lock.obj"
	-@erase "$(OUTDIR)\mod_dav.exp"
	-@erase "$(OUTDIR)\mod_dav.ilk"
	-@erase "$(OUTDIR)\mod_dav.lib"
	-@erase "$(OUTDIR)\mod_dav.map"
	-@erase "$(OUTDIR)\mod_dav.pdb"
	-@erase "$(OUTDIR)\mod_dav.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\..\srclib\aputil" /I\
 "..\..\..\srclib\sdbm" /I "..\..\..\srclib\expat-lite" /I\
 "..\..\..\srclib\apr\include" /I "../../../srclib/apr-util/include" /I\
 "..\..\..\include" /I "..\..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS"\
 /D "DAV_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows\
 /dll /incremental:yes /pdb:"$(OUTDIR)\mod_dav.pdb" /map:"$(INTDIR)\mod_dav.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\mod_dav.so"\
 /implib:"$(OUTDIR)\mod_dav.lib" /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav 
LINK32_OBJS= \
	"$(INTDIR)\liveprop.obj" \
	"$(INTDIR)\mod_dav.obj" \
	"$(INTDIR)\props.obj" \
	"$(INTDIR)\providers.obj" \
	"$(INTDIR)\std_liveprop.obj" \
	"$(INTDIR)\util.obj" \
	"$(INTDIR)\util_lock.obj" \
	"..\..\..\Debug\libhttpd.lib" \
	"..\..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\..\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\mod_dav.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "mod_dav - Win32 Release" || "$(CFG)" ==\
 "mod_dav - Win32 Debug"
SOURCE=.\liveprop.c
DEP_CPP_LIVEP=\
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
	".\mod_dav.h"\
	
NODEP_CPP_LIVEP=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\liveprop.obj" : $(SOURCE) $(DEP_CPP_LIVEP) "$(INTDIR)"


SOURCE=.\mod_dav.c
DEP_CPP_MOD_D=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_config.h"\
	"..\..\..\include\http_core.h"\
	"..\..\..\include\http_log.h"\
	"..\..\..\include\http_main.h"\
	"..\..\..\include\http_protocol.h"\
	"..\..\..\include\http_request.h"\
	"..\..\..\include\httpd.h"\
	"..\..\..\include\pcreposix.h"\
	"..\..\..\include\util_cfgtree.h"\
	"..\..\..\include\util_filter.h"\
	"..\..\..\include\util_script.h"\
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
	"..\..\..\srclib\apr\include\apr_lib.h"\
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
	".\mod_dav.h"\
	
NODEP_CPP_MOD_D=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\mod_dav.obj" : $(SOURCE) $(DEP_CPP_MOD_D) "$(INTDIR)"


SOURCE=.\props.c
DEP_CPP_PROPS=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_log.h"\
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
	"..\..\..\srclib\apr\include\apr_want.h"\
	".\mod_dav.h"\
	
NODEP_CPP_PROPS=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\props.obj" : $(SOURCE) $(DEP_CPP_PROPS) "$(INTDIR)"


SOURCE=.\providers.c
DEP_CPP_PROVI=\
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
	"..\..\..\srclib\apr\include\apr_tables.h"\
	"..\..\..\srclib\apr\include\apr_time.h"\
	"..\..\..\srclib\apr\include\apr_user.h"\
	"..\..\..\srclib\apr\include\apr_want.h"\
	".\mod_dav.h"\
	
NODEP_CPP_PROVI=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\providers.obj" : $(SOURCE) $(DEP_CPP_PROVI) "$(INTDIR)"


SOURCE=.\std_liveprop.c
DEP_CPP_STD_L=\
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
	".\mod_dav.h"\
	
NODEP_CPP_STD_L=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\std_liveprop.obj" : $(SOURCE) $(DEP_CPP_STD_L) "$(INTDIR)"


SOURCE=.\util.c
DEP_CPP_UTIL_=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_config.h"\
	"..\..\..\include\http_log.h"\
	"..\..\..\include\http_protocol.h"\
	"..\..\..\include\http_request.h"\
	"..\..\..\include\http_vhost.h"\
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
	"..\..\..\srclib\apr\include\apr_dso.h"\
	"..\..\..\srclib\apr\include\apr_errno.h"\
	"..\..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\..\srclib\apr\include\apr_general.h"\
	"..\..\..\srclib\apr\include\apr_hash.h"\
	"..\..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\..\srclib\apr\include\apr_lib.h"\
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
	".\mod_dav.h"\
	
NODEP_CPP_UTIL_=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\util.obj" : $(SOURCE) $(DEP_CPP_UTIL_) "$(INTDIR)"


SOURCE=.\util_lock.c
DEP_CPP_UTIL_L=\
	"..\..\..\include\ap_config.h"\
	"..\..\..\include\ap_mmn.h"\
	"..\..\..\include\ap_release.h"\
	"..\..\..\include\http_config.h"\
	"..\..\..\include\http_core.h"\
	"..\..\..\include\http_log.h"\
	"..\..\..\include\http_protocol.h"\
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
	".\mod_dav.h"\
	
NODEP_CPP_UTIL_L=\
	"..\..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\util_lock.obj" : $(SOURCE) $(DEP_CPP_UTIL_L) "$(INTDIR)"


!IF  "$(CFG)" == "mod_dav - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\dav\main"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\dav\main"

!ELSEIF  "$(CFG)" == "mod_dav - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\dav\main"

"libapr - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\dav\main"

!ENDIF 

!IF  "$(CFG)" == "mod_dav - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\dav\main"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\dav\main"

!ELSEIF  "$(CFG)" == "mod_dav - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\dav\main"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\dav\main"

!ENDIF 

!IF  "$(CFG)" == "mod_dav - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\dav\main"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\dav\main"

!ELSEIF  "$(CFG)" == "mod_dav - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\dav\main"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\../../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\dav\main"

!ENDIF 


!ENDIF 

