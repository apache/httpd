# Microsoft Developer Studio Generated NMAKE File, Based on mod_ssl.dsp
!IF "$(CFG)" == ""
CFG=mod_ssl - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_ssl - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_ssl - Win32 Release" && "$(CFG)" !=\
 "mod_ssl - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_ssl.mak" CFG="mod_ssl - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_ssl - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_ssl - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_ssl.so"

!ELSE 

ALL : "pcre - Win32 Release" "libhttpd - Win32 Release"\
 "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_ssl.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" "pcre - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_ssl.idb"
	-@erase "$(INTDIR)\mod_ssl.obj"
	-@erase "$(INTDIR)\ssl_engine_config.obj"
	-@erase "$(INTDIR)\ssl_engine_dh.obj"
	-@erase "$(INTDIR)\ssl_engine_ds.obj"
	-@erase "$(INTDIR)\ssl_engine_ext.obj"
	-@erase "$(INTDIR)\ssl_engine_init.obj"
	-@erase "$(INTDIR)\ssl_engine_io.obj"
	-@erase "$(INTDIR)\ssl_engine_kernel.obj"
	-@erase "$(INTDIR)\ssl_engine_log.obj"
	-@erase "$(INTDIR)\ssl_engine_mutex.obj"
	-@erase "$(INTDIR)\ssl_engine_pphrase.obj"
	-@erase "$(INTDIR)\ssl_engine_rand.obj"
	-@erase "$(INTDIR)\ssl_engine_vars.obj"
	-@erase "$(INTDIR)\ssl_expr.obj"
	-@erase "$(INTDIR)\ssl_expr_eval.obj"
	-@erase "$(INTDIR)\ssl_expr_parse.obj"
	-@erase "$(INTDIR)\ssl_expr_scan.obj"
	-@erase "$(INTDIR)\ssl_scache.obj"
	-@erase "$(INTDIR)\ssl_scache_dbm.obj"
	-@erase "$(INTDIR)\ssl_scache_shmcb.obj"
	-@erase "$(INTDIR)\ssl_scache_shmht.obj"
	-@erase "$(INTDIR)\ssl_util.obj"
	-@erase "$(INTDIR)\ssl_util_ssl.obj"
	-@erase "$(INTDIR)\ssl_util_table.obj"
	-@erase "$(OUTDIR)\mod_ssl.exp"
	-@erase "$(OUTDIR)\mod_ssl.lib"
	-@erase "$(OUTDIR)\mod_ssl.map"
	-@erase "$(OUTDIR)\mod_ssl.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "../../include" /I "../../os/win32" /I\
 "../../server/mpm/winnt" /I "../../srclib/apr/include" /I\
 "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "NOCRYPT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_ssl" /FD\
 /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_ssl.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_ssl.pdb" /map:"$(INTDIR)\mod_ssl.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_ssl.so" /implib:"$(OUTDIR)\mod_ssl.lib"\
 /libpath:"../../srclib/openssl/out32dll"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl 
LINK32_OBJS= \
	"$(INTDIR)\mod_ssl.obj" \
	"$(INTDIR)\ssl_engine_config.obj" \
	"$(INTDIR)\ssl_engine_dh.obj" \
	"$(INTDIR)\ssl_engine_ds.obj" \
	"$(INTDIR)\ssl_engine_ext.obj" \
	"$(INTDIR)\ssl_engine_init.obj" \
	"$(INTDIR)\ssl_engine_io.obj" \
	"$(INTDIR)\ssl_engine_kernel.obj" \
	"$(INTDIR)\ssl_engine_log.obj" \
	"$(INTDIR)\ssl_engine_mutex.obj" \
	"$(INTDIR)\ssl_engine_pphrase.obj" \
	"$(INTDIR)\ssl_engine_rand.obj" \
	"$(INTDIR)\ssl_engine_vars.obj" \
	"$(INTDIR)\ssl_expr.obj" \
	"$(INTDIR)\ssl_expr_eval.obj" \
	"$(INTDIR)\ssl_expr_parse.obj" \
	"$(INTDIR)\ssl_expr_scan.obj" \
	"$(INTDIR)\ssl_scache.obj" \
	"$(INTDIR)\ssl_scache_dbm.obj" \
	"$(INTDIR)\ssl_scache_shmcb.obj" \
	"$(INTDIR)\ssl_scache_shmht.obj" \
	"$(INTDIR)\ssl_util.obj" \
	"$(INTDIR)\ssl_util_ssl.obj" \
	"$(INTDIR)\ssl_util_table.obj" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\srclib\apr\Release\libapr.lib" \
	"..\..\srclib\pcre\LibR\pcre.lib"

"$(OUTDIR)\mod_ssl.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_ssl.so"

!ELSE 

ALL : "pcre - Win32 Debug" "libhttpd - Win32 Debug" "libaprutil - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\mod_ssl.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" "pcre - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_ssl.idb"
	-@erase "$(INTDIR)\mod_ssl.obj"
	-@erase "$(INTDIR)\ssl_engine_config.obj"
	-@erase "$(INTDIR)\ssl_engine_dh.obj"
	-@erase "$(INTDIR)\ssl_engine_ds.obj"
	-@erase "$(INTDIR)\ssl_engine_ext.obj"
	-@erase "$(INTDIR)\ssl_engine_init.obj"
	-@erase "$(INTDIR)\ssl_engine_io.obj"
	-@erase "$(INTDIR)\ssl_engine_kernel.obj"
	-@erase "$(INTDIR)\ssl_engine_log.obj"
	-@erase "$(INTDIR)\ssl_engine_mutex.obj"
	-@erase "$(INTDIR)\ssl_engine_pphrase.obj"
	-@erase "$(INTDIR)\ssl_engine_rand.obj"
	-@erase "$(INTDIR)\ssl_engine_vars.obj"
	-@erase "$(INTDIR)\ssl_expr.obj"
	-@erase "$(INTDIR)\ssl_expr_eval.obj"
	-@erase "$(INTDIR)\ssl_expr_parse.obj"
	-@erase "$(INTDIR)\ssl_expr_scan.obj"
	-@erase "$(INTDIR)\ssl_scache.obj"
	-@erase "$(INTDIR)\ssl_scache_dbm.obj"
	-@erase "$(INTDIR)\ssl_scache_shmcb.obj"
	-@erase "$(INTDIR)\ssl_scache_shmht.obj"
	-@erase "$(INTDIR)\ssl_util.obj"
	-@erase "$(INTDIR)\ssl_util_ssl.obj"
	-@erase "$(INTDIR)\ssl_util_table.obj"
	-@erase "$(OUTDIR)\mod_ssl.exp"
	-@erase "$(OUTDIR)\mod_ssl.lib"
	-@erase "$(OUTDIR)\mod_ssl.map"
	-@erase "$(OUTDIR)\mod_ssl.pdb"
	-@erase "$(OUTDIR)\mod_ssl.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../os/win32" /I\
 "../../server/mpm/winnt" /I "../../srclib/apr/include" /I\
 "../../srclib/apr-util/include" /I "../../srclib/openssl/inc32" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "NOCRYPT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_ssl" /FD\
 /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_ssl.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_ssl.pdb" /map:"$(INTDIR)\mod_ssl.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\mod_ssl.so"\
 /implib:"$(OUTDIR)\mod_ssl.lib" /libpath:"../../srclib/openssl/out32dll.dbg"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_ssl 
LINK32_OBJS= \
	"$(INTDIR)\mod_ssl.obj" \
	"$(INTDIR)\ssl_engine_config.obj" \
	"$(INTDIR)\ssl_engine_dh.obj" \
	"$(INTDIR)\ssl_engine_ds.obj" \
	"$(INTDIR)\ssl_engine_ext.obj" \
	"$(INTDIR)\ssl_engine_init.obj" \
	"$(INTDIR)\ssl_engine_io.obj" \
	"$(INTDIR)\ssl_engine_kernel.obj" \
	"$(INTDIR)\ssl_engine_log.obj" \
	"$(INTDIR)\ssl_engine_mutex.obj" \
	"$(INTDIR)\ssl_engine_pphrase.obj" \
	"$(INTDIR)\ssl_engine_rand.obj" \
	"$(INTDIR)\ssl_engine_vars.obj" \
	"$(INTDIR)\ssl_expr.obj" \
	"$(INTDIR)\ssl_expr_eval.obj" \
	"$(INTDIR)\ssl_expr_parse.obj" \
	"$(INTDIR)\ssl_expr_scan.obj" \
	"$(INTDIR)\ssl_scache.obj" \
	"$(INTDIR)\ssl_scache_dbm.obj" \
	"$(INTDIR)\ssl_scache_shmcb.obj" \
	"$(INTDIR)\ssl_scache_shmht.obj" \
	"$(INTDIR)\ssl_util.obj" \
	"$(INTDIR)\ssl_util_ssl.obj" \
	"$(INTDIR)\ssl_util_table.obj" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\srclib\apr\Debug\libapr.lib" \
	"..\..\srclib\pcre\LibD\pcre.lib"

"$(OUTDIR)\mod_ssl.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "mod_ssl - Win32 Release" || "$(CFG)" ==\
 "mod_ssl - Win32 Debug"
SOURCE=.\mod_ssl.c
DEP_CPP_MOD_S=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_md5.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
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
	"..\..\srclib\apr\include\apr_sms.h"\
	"..\..\srclib\apr\include\apr_strings.h"\
	"..\..\srclib\apr\include\apr_tables.h"\
	"..\..\srclib\apr\include\apr_thread_proc.h"\
	"..\..\srclib\apr\include\apr_time.h"\
	"..\..\srclib\apr\include\apr_user.h"\
	"..\..\srclib\apr\include\apr_want.h"\
	"..\..\srclib\apr\include\apr_xlate.h"\
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_MOD_S=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\mod_ssl.obj" : $(SOURCE) $(DEP_CPP_MOD_S) "$(INTDIR)"


SOURCE=.\ssl_engine_config.c
DEP_CPP_SSL_E=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_E=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_config.obj" : $(SOURCE) $(DEP_CPP_SSL_E) "$(INTDIR)"


SOURCE=.\ssl_engine_dh.c
DEP_CPP_SSL_EN=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_EN=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_dh.obj" : $(SOURCE) $(DEP_CPP_SSL_EN) "$(INTDIR)"


SOURCE=.\ssl_engine_ds.c
DEP_CPP_SSL_ENG=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENG=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_ds.obj" : $(SOURCE) $(DEP_CPP_SSL_ENG) "$(INTDIR)"


SOURCE=.\ssl_engine_ext.c
DEP_CPP_SSL_ENGI=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
	"..\..\srclib\apr-util\include\apr_hooks.h"\
	"..\..\srclib\apr-util\include\apr_optional.h"\
	"..\..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\..\srclib\apr-util\include\apr_ring.h"\
	"..\..\srclib\apr-util\include\apr_uri.h"\
	"..\..\srclib\apr-util\include\apu.h"\
	"..\..\srclib\apr\include\apr.h"\
	"..\..\srclib\apr\include\apr_dso.h"\
	"..\..\srclib\apr\include\apr_errno.h"\
	"..\..\srclib\apr\include\apr_file_info.h"\
	"..\..\srclib\apr\include\apr_file_io.h"\
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	"..\loggers\mod_log_config.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGI=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_ext.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGI) "$(INTDIR)"


SOURCE=.\ssl_engine_init.c
DEP_CPP_SSL_ENGIN=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGIN=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_init.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGIN) "$(INTDIR)"


SOURCE=.\ssl_engine_io.c
DEP_CPP_SSL_ENGINE=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_io.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE) "$(INTDIR)"


SOURCE=.\ssl_engine_kernel.c
DEP_CPP_SSL_ENGINE_=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_kernel.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_)\
 "$(INTDIR)"


SOURCE=.\ssl_engine_log.c
DEP_CPP_SSL_ENGINE_L=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_L=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_log.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_L) "$(INTDIR)"


SOURCE=.\ssl_engine_mutex.c
DEP_CPP_SSL_ENGINE_M=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_M=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_mutex.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_M)\
 "$(INTDIR)"


SOURCE=.\ssl_engine_pphrase.c
DEP_CPP_SSL_ENGINE_P=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_P=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_pphrase.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_P)\
 "$(INTDIR)"


SOURCE=.\ssl_engine_rand.c
DEP_CPP_SSL_ENGINE_R=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_R=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_rand.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_R) "$(INTDIR)"


SOURCE=.\ssl_engine_vars.c
DEP_CPP_SSL_ENGINE_V=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_ENGINE_V=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_engine_vars.obj" : $(SOURCE) $(DEP_CPP_SSL_ENGINE_V) "$(INTDIR)"


SOURCE=.\ssl_expr.c
DEP_CPP_SSL_EX=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_EX=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_expr.obj" : $(SOURCE) $(DEP_CPP_SSL_EX) "$(INTDIR)"


SOURCE=.\ssl_expr_eval.c
DEP_CPP_SSL_EXP=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_EXP=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_expr_eval.obj" : $(SOURCE) $(DEP_CPP_SSL_EXP) "$(INTDIR)"


SOURCE=.\ssl_expr_parse.c
DEP_CPP_SSL_EXPR=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_EXPR=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_expr_parse.obj" : $(SOURCE) $(DEP_CPP_SSL_EXPR) "$(INTDIR)"


SOURCE=.\ssl_expr_scan.c
DEP_CPP_SSL_EXPR_=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_expr_parse.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_EXPR_=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_expr_scan.obj" : $(SOURCE) $(DEP_CPP_SSL_EXPR_) "$(INTDIR)"\
 ".\ssl_expr_parse.h"


SOURCE=.\ssl_scache.c
DEP_CPP_SSL_S=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_S=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_scache.obj" : $(SOURCE) $(DEP_CPP_SSL_S) "$(INTDIR)"


SOURCE=.\ssl_scache_dbm.c
DEP_CPP_SSL_SC=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_SC=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_scache_dbm.obj" : $(SOURCE) $(DEP_CPP_SSL_SC) "$(INTDIR)"


SOURCE=.\ssl_scache_shmcb.c
DEP_CPP_SSL_SCA=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_SCA=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_scache_shmcb.obj" : $(SOURCE) $(DEP_CPP_SSL_SCA) "$(INTDIR)"


SOURCE=.\ssl_scache_shmht.c
DEP_CPP_SSL_SCAC=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_SCAC=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_scache_shmht.obj" : $(SOURCE) $(DEP_CPP_SSL_SCAC) "$(INTDIR)"


SOURCE=.\ssl_util.c
DEP_CPP_SSL_U=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_U=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_util.obj" : $(SOURCE) $(DEP_CPP_SSL_U) "$(INTDIR)"


SOURCE=.\ssl_util_ssl.c
DEP_CPP_SSL_UT=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\pcreposix.h"\
	"..\..\include\scoreboard.h"\
	"..\..\include\util_cfgtree.h"\
	"..\..\include\util_filter.h"\
	"..\..\include\util_script.h"\
	"..\..\os\win32\os.h"\
	"..\..\server\mpm\winnt\mpm.h"\
	"..\..\server\mpm\winnt\mpm_default.h"\
	"..\..\srclib\apr-util\include\apr_buckets.h"\
	"..\..\srclib\apr-util\include\apr_dbm.h"\
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
	"..\..\srclib\apr\include\apr_fnmatch.h"\
	"..\..\srclib\apr\include\apr_general.h"\
	"..\..\srclib\apr\include\apr_hash.h"\
	"..\..\srclib\apr\include\apr_inherit.h"\
	"..\..\srclib\apr\include\apr_lib.h"\
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
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\conf.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os.h"\
	"..\..\srclib\openssl\inc32\openssl\e_os2.h"\
	"..\..\srclib\openssl\inc32\openssl\ebcdic.h"\
	"..\..\srclib\openssl\inc32\openssl\err.h"\
	"..\..\srclib\openssl\inc32\openssl\evp.h"\
	"..\..\srclib\openssl\inc32\openssl\idea.h"\
	"..\..\srclib\openssl\inc32\openssl\lhash.h"\
	"..\..\srclib\openssl\inc32\openssl\md2.h"\
	"..\..\srclib\openssl\inc32\openssl\md4.h"\
	"..\..\srclib\openssl\inc32\openssl\md5.h"\
	"..\..\srclib\openssl\inc32\openssl\mdc2.h"\
	"..\..\srclib\openssl\inc32\openssl\obj_mac.h"\
	"..\..\srclib\openssl\inc32\openssl\objects.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslconf.h"\
	"..\..\srclib\openssl\inc32\openssl\opensslv.h"\
	"..\..\srclib\openssl\inc32\openssl\pem.h"\
	"..\..\srclib\openssl\inc32\openssl\pem2.h"\
	"..\..\srclib\openssl\inc32\openssl\pkcs7.h"\
	"..\..\srclib\openssl\inc32\openssl\rand.h"\
	"..\..\srclib\openssl\inc32\openssl\rc2.h"\
	"..\..\srclib\openssl\inc32\openssl\rc4.h"\
	"..\..\srclib\openssl\inc32\openssl\rc5.h"\
	"..\..\srclib\openssl\inc32\openssl\ripemd.h"\
	"..\..\srclib\openssl\inc32\openssl\rsa.h"\
	"..\..\srclib\openssl\inc32\openssl\safestack.h"\
	"..\..\srclib\openssl\inc32\openssl\sha.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl2.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl23.h"\
	"..\..\srclib\openssl\inc32\openssl\ssl3.h"\
	"..\..\srclib\openssl\inc32\openssl\stack.h"\
	"..\..\srclib\openssl\inc32\openssl\symhacks.h"\
	"..\..\srclib\openssl\inc32\openssl\tls1.h"\
	"..\..\srclib\openssl\inc32\openssl\x509.h"\
	"..\..\srclib\openssl\inc32\openssl\x509_vfy.h"\
	"..\..\srclib\openssl\inc32\openssl\x509v3.h"\
	".\mod_ssl.h"\
	".\ssl_expr.h"\
	".\ssl_util_ssl.h"\
	".\ssl_util_table.h"\
	
NODEP_CPP_SSL_UT=\
	"..\..\include\ap_config_auto.h"\
	"..\..\srclib\openssl\inc32\openssl\MacSocket.h"\
	

"$(INTDIR)\ssl_util_ssl.obj" : $(SOURCE) $(DEP_CPP_SSL_UT) "$(INTDIR)"


SOURCE=.\ssl_util_table.c
DEP_CPP_SSL_UTI=\
	".\ssl_util_table.h"\
	

"$(INTDIR)\ssl_util_table.obj" : $(SOURCE) $(DEP_CPP_SSL_UTI) "$(INTDIR)"


SOURCE=.\ssl_expr_parse.y

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

InputPath=.\ssl_expr_parse.y

"ssl_expr_parse.c"	"ssl_expr_parse.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	bison -y -d ssl_expr_parse.y 
	sed -e "s;yy;ssl_expr_yy;g" -e\
  "/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d" <y.tab.c\
  >ssl_expr_parse.c 
	del y.tab.c 
	sed -e "s;yy;ssl_expr_yy;g" <y.tab.h >ssl_expr_parse.h 
	del y.tab.h 
	

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

InputPath=.\ssl_expr_parse.y

"ssl_expr_parse.c"	"ssl_expr_parse.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	bison -y -d ssl_expr_parse.y 
	sed -e "s;yy;ssl_expr_yy;g" -e\
  "/#if defined(c_plusplus) || defined(__cplusplus)/,/#endif/d" <y.tab.c\
  >ssl_expr_parse.c 
	del y.tab.c 
	sed -e "s;yy;ssl_expr_yy;g" <y.tab.h >ssl_expr_parse.h 
	del y.tab.h 
	

!ENDIF 

SOURCE=.\ssl_expr_scan.l

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

InputPath=.\ssl_expr_scan.l

"ssl_expr_scan.c"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	flex -Pssl_expr_yy -s -B ssl_expr_scan.l 
	sed -e "/$$Header:/d" <lex.ssl_expr_yy.c >ssl_expr_scan.c 
	del lex.ssl_expr_yy.c 
	

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

InputPath=.\ssl_expr_scan.l

"ssl_expr_scan.c"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	flex -Pssl_expr_yy -s -B ssl_expr_scan.l 
	sed -e "/$$Header:/d" <lex.ssl_expr_yy.c >ssl_expr_scan.c 
	del lex.ssl_expr_yy.c 
	

!ENDIF 

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\ssl"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\ssl"

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\ssl"

"libapr - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\ssl"

!ENDIF 

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\ssl"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\ssl"

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\ssl"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\ssl"

!ENDIF 

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\ssl"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\ssl"

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\ssl"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\ssl"

!ENDIF 

!IF  "$(CFG)" == "mod_ssl - Win32 Release"

"pcre - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Release" 
   cd "..\..\modules\ssl"

"pcre - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\ssl"

!ELSEIF  "$(CFG)" == "mod_ssl - Win32 Debug"

"pcre - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Debug" 
   cd "..\..\modules\ssl"

"pcre - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\ssl"

!ENDIF 


!ENDIF 

