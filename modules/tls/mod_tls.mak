# Microsoft Developer Studio Generated NMAKE File, Based on mod_tls.dsp
!IF "$(CFG)" == ""
CFG=mod_tls - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_tls - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_tls - Win32 Release" && "$(CFG)" !=\
 "mod_tls - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_tls.mak" CFG="mod_tls - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_tls - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_tls - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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

!IF  "$(CFG)" == "mod_tls - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_tls.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\mod_tls.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_tls.idb"
	-@erase "$(INTDIR)\mod_tls.obj"
	-@erase "$(INTDIR)\openssl_state_machine.obj"
	-@erase "$(OUTDIR)\mod_tls.exp"
	-@erase "$(OUTDIR)\mod_tls.lib"
	-@erase "$(OUTDIR)\mod_tls.map"
	-@erase "$(OUTDIR)\mod_tls.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "../../include" /I "../../os/win32" /I\
 "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I\
 "../../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_tls" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_tls.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_tls.pdb" /map:"$(INTDIR)\mod_tls.map"\
 /machine:I386 /out:"$(OUTDIR)\mod_tls.so" /implib:"$(OUTDIR)\mod_tls.lib"\
 /libpath:"../../srclib/openssl/out32dll"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_tls 
LINK32_OBJS= \
	"$(INTDIR)\mod_tls.obj" \
	"$(INTDIR)\openssl_state_machine.obj" \
	"..\..\Release\libhttpd.lib" \
	"..\..\srclib\apr-util\Release\libaprutil.lib" \
	"..\..\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\mod_tls.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_tls - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_tls.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\mod_tls.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_tls.idb"
	-@erase "$(INTDIR)\mod_tls.obj"
	-@erase "$(INTDIR)\openssl_state_machine.obj"
	-@erase "$(OUTDIR)\mod_tls.exp"
	-@erase "$(OUTDIR)\mod_tls.lib"
	-@erase "$(OUTDIR)\mod_tls.map"
	-@erase "$(OUTDIR)\mod_tls.pdb"
	-@erase "$(OUTDIR)\mod_tls.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../os/win32" /I\
 "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I\
 "../../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_tls" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_tls.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ssleay32.lib libeay32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\mod_tls.pdb" /map:"$(INTDIR)\mod_tls.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\mod_tls.so"\
 /implib:"$(OUTDIR)\mod_tls.lib" /libpath:"../../srclib/openssl/out32dll.dbg"\
 /base:@..\..\os\win32\BaseAddr.ref,mod_tls 
LINK32_OBJS= \
	"$(INTDIR)\mod_tls.obj" \
	"$(INTDIR)\openssl_state_machine.obj" \
	"..\..\Debug\libhttpd.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil.lib" \
	"..\..\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\mod_tls.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "mod_tls - Win32 Release" || "$(CFG)" ==\
 "mod_tls - Win32 Debug"

!IF  "$(CFG)" == "mod_tls - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\tls"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\..\modules\tls"

!ELSEIF  "$(CFG)" == "mod_tls - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\tls"

"libapr - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\..\modules\tls"

!ENDIF 

!IF  "$(CFG)" == "mod_tls - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\..\modules\tls"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\..\modules\tls"

!ELSEIF  "$(CFG)" == "mod_tls - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\tls"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\..\modules\tls"

!ENDIF 

!IF  "$(CFG)" == "mod_tls - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\tls"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd ".\modules\tls"

!ELSEIF  "$(CFG)" == "mod_tls - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\tls"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\../..\httpd-2.0"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd ".\modules\tls"

!ENDIF 

SOURCE=.\mod_tls.c
DEP_CPP_MOD_T=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_release.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_connection.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_protocol.h"\
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
	".\openssl_state_machine.h"\
	
NODEP_CPP_MOD_T=\
	"..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\mod_tls.obj" : $(SOURCE) $(DEP_CPP_MOD_T) "$(INTDIR)"


SOURCE=.\openssl_state_machine.c
DEP_CPP_OPENS=\
	"..\..\srclib\apr\include\apr.h"\
	"..\..\srclib\openssl\inc32\openssl\asn1.h"\
	"..\..\srclib\openssl\inc32\openssl\bio.h"\
	"..\..\srclib\openssl\inc32\openssl\blowfish.h"\
	"..\..\srclib\openssl\inc32\openssl\bn.h"\
	"..\..\srclib\openssl\inc32\openssl\buffer.h"\
	"..\..\srclib\openssl\inc32\openssl\cast.h"\
	"..\..\srclib\openssl\inc32\openssl\comp.h"\
	"..\..\srclib\openssl\inc32\openssl\crypto.h"\
	"..\..\srclib\openssl\inc32\openssl\des.h"\
	"..\..\srclib\openssl\inc32\openssl\dh.h"\
	"..\..\srclib\openssl\inc32\openssl\dsa.h"\
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
	".\openssl_state_machine.h"\
	

"$(INTDIR)\openssl_state_machine.obj" : $(SOURCE) $(DEP_CPP_OPENS) "$(INTDIR)"



!ENDIF 

