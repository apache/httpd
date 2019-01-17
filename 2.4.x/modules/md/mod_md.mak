# Microsoft Developer Studio Generated NMAKE File, Based on mod_md.dsp
!IF "$(CFG)" == ""
CFG=mod_md - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_md - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_md - Win32 Release" && "$(CFG)" != "mod_md - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
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
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF "$(_HAVE_OSSL110)" == "1"
SSLCRP=libcrypto
SSLLIB=libssl
SSLINC=/I ../../srclib/openssl/include
SSLBIN=/libpath:../../srclib/openssl
!ELSE 
SSLCRP=libeay32
SSLLIB=ssleay32
SSLINC=/I ../../srclib/openssl/inc32
SSLBIN=/libpath:../../srclib/openssl/out32dll
!ENDIF 

!IF  "$(CFG)" == "mod_md - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_md.so"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_md.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\md_acme.obj"
	-@erase "$(INTDIR)\md_acme_acct.obj"
	-@erase "$(INTDIR)\md_acme_authz.obj"
	-@erase "$(INTDIR)\md_acme_drive.obj"
	-@erase "$(INTDIR)\md_core.obj"
	-@erase "$(INTDIR)\md_crypt.obj"
	-@erase "$(INTDIR)\md_curl.obj"
	-@erase "$(INTDIR)\md_http.obj"
	-@erase "$(INTDIR)\md_json.obj"
	-@erase "$(INTDIR)\md_jws.obj"
	-@erase "$(INTDIR)\md_log.obj"
	-@erase "$(INTDIR)\md_reg.obj"
	-@erase "$(INTDIR)\md_store.obj"
	-@erase "$(INTDIR)\md_store_fs.obj"
	-@erase "$(INTDIR)\md_util.obj"
	-@erase "$(INTDIR)\mod_md.obj"
	-@erase "$(INTDIR)\mod_md.res"
	-@erase "$(INTDIR)\mod_md_config.obj"
	-@erase "$(INTDIR)\mod_md_os.obj"
	-@erase "$(INTDIR)\mod_md_src.idb"
	-@erase "$(INTDIR)\mod_md_src.pdb"
	-@erase "$(OUTDIR)\mod_md.exp"
	-@erase "$(OUTDIR)\mod_md.lib"
	-@erase "$(OUTDIR)\mod_md.pdb"
	-@erase "$(OUTDIR)\mod_md.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../server/mpm/winnt" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" $(SSLINC) /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../ssl" /I "../core" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_md_src" /FD /I " ../ssl" /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_md.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME=mod_md.so /d LONG_NAME=Letsencrypt module for Apache 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_md.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib $(SSLCRP).lib $(SSLLIB).lib jansson.lib libcurl.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_md.pdb" /debug  /out:"$(OUTDIR)\mod_md.so" /implib:"$(OUTDIR)\mod_md.lib" /libpath:"../../srclib/apr/Release" /libpath:"../../srclib/apr-util/Release" /libpath:"../../Release/" $(SSLBIN) /libpath:"../../srclib/jansson/lib" /libpath:"../../srclib/curl/lib" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_md.obj" \
	"$(INTDIR)\mod_md_config.obj" \
	"$(INTDIR)\mod_md_os.obj" \
	"$(INTDIR)\md_core.obj" \
	"$(INTDIR)\md_crypt.obj" \
	"$(INTDIR)\md_curl.obj" \
	"$(INTDIR)\md_http.obj" \
	"$(INTDIR)\md_json.obj" \
	"$(INTDIR)\md_jws.obj" \
	"$(INTDIR)\md_log.obj" \
	"$(INTDIR)\md_reg.obj" \
	"$(INTDIR)\md_store.obj" \
	"$(INTDIR)\md_store_fs.obj" \
	"$(INTDIR)\md_util.obj" \
	"$(INTDIR)\md_acme.obj" \
	"$(INTDIR)\md_acme_acct.obj" \
	"$(INTDIR)\md_acme_authz.obj" \
	"$(INTDIR)\md_acme_drive.obj" \
	"$(INTDIR)\mod_md.res" \
	"..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\Release\libhttpd.lib"

"$(OUTDIR)\mod_md.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_md.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

$(DS_POSTBUILD_DEP) : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_md.so"
   if exist .\Release\mod_md.so.manifest mt.exe -manifest .\Release\mod_md.so.manifest -outputresource:.\Release\mod_md.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_md.so"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_md.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\md_acme.obj"
	-@erase "$(INTDIR)\md_acme_acct.obj"
	-@erase "$(INTDIR)\md_acme_authz.obj"
	-@erase "$(INTDIR)\md_acme_drive.obj"
	-@erase "$(INTDIR)\md_core.obj"
	-@erase "$(INTDIR)\md_crypt.obj"
	-@erase "$(INTDIR)\md_curl.obj"
	-@erase "$(INTDIR)\md_http.obj"
	-@erase "$(INTDIR)\md_json.obj"
	-@erase "$(INTDIR)\md_jws.obj"
	-@erase "$(INTDIR)\md_log.obj"
	-@erase "$(INTDIR)\md_reg.obj"
	-@erase "$(INTDIR)\md_store.obj"
	-@erase "$(INTDIR)\md_store_fs.obj"
	-@erase "$(INTDIR)\md_util.obj"
	-@erase "$(INTDIR)\mod_md.obj"
	-@erase "$(INTDIR)\mod_md.res"
	-@erase "$(INTDIR)\mod_md_config.obj"
	-@erase "$(INTDIR)\mod_md_os.obj"
	-@erase "$(INTDIR)\mod_md_src.idb"
	-@erase "$(INTDIR)\mod_md_src.pdb"
	-@erase "$(OUTDIR)\mod_md.exp"
	-@erase "$(OUTDIR)\mod_md.lib"
	-@erase "$(OUTDIR)\mod_md.pdb"
	-@erase "$(OUTDIR)\mod_md.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" $(SSLINC) /I "../../srclib/jansson/include" /I "../../srclib/curl/include" /I "../core" /I "../ssl" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_md_src" /FD /EHsc /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_md.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME=mod_md.so /d LONG_NAME=http2_module for Apache 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_md.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib libhttpd.lib libapr-1.lib libaprutil-1.lib $(SSLCRP).lib $(SSLLIB).lib jansson_d.lib libcurl_debug.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_md.pdb" /debug  /out:"$(OUTDIR)\mod_md.so" /implib:"$(OUTDIR)\mod_md.lib" $(SSLBIN) /libpath:"../../srclib/jansson/lib" /libpath:"../../srclib/curl/lib" /base:@..\..\os\win32\BaseAddr.ref,mod_md.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_md.obj" \
	"$(INTDIR)\mod_md_config.obj" \
	"$(INTDIR)\mod_md_os.obj" \
	"$(INTDIR)\md_core.obj" \
	"$(INTDIR)\md_crypt.obj" \
	"$(INTDIR)\md_curl.obj" \
	"$(INTDIR)\md_http.obj" \
	"$(INTDIR)\md_json.obj" \
	"$(INTDIR)\md_jws.obj" \
	"$(INTDIR)\md_log.obj" \
	"$(INTDIR)\md_reg.obj" \
	"$(INTDIR)\md_store.obj" \
	"$(INTDIR)\md_store_fs.obj" \
	"$(INTDIR)\md_util.obj" \
	"$(INTDIR)\md_acme.obj" \
	"$(INTDIR)\md_acme_acct.obj" \
	"$(INTDIR)\md_acme_authz.obj" \
	"$(INTDIR)\md_acme_drive.obj" \
	"$(INTDIR)\mod_md.res" \
	"..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\Debug\libhttpd.lib"

"$(OUTDIR)\mod_md.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_md.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

$(DS_POSTBUILD_DEP) : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_md.so"
   if exist .\Debug\mod_md.so.manifest mt.exe -manifest .\Debug\mod_md.so.manifest -outputresource:.\Debug\mod_md.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_md.dep")
!INCLUDE "mod_md.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_md.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_md - Win32 Release" || "$(CFG)" == "mod_md - Win32 Debug"

!IF  "$(CFG)" == "mod_md - Win32 Release"

"libapr - Win32 Release" : 
   cd "..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\md"

"libapr - Win32 ReleaseCLEAN" : 
   cd "..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\md"

!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"

"libapr - Win32 Debug" : 
   cd "..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\md"

"libapr - Win32 DebugCLEAN" : 
   cd "..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\md"

!ENDIF 

!IF  "$(CFG)" == "mod_md - Win32 Release"

"libaprutil - Win32 Release" : 
   cd "..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\md"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd "..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\md"

!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd "..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\md"

"libaprutil - Win32 DebugCLEAN" : 
   cd "..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\md"

!ENDIF 

!IF  "$(CFG)" == "mod_md - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\md"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\md"

!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\md"

"libhttpd - Win32 DebugCLEAN" : 
   cd "..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\md"

!ENDIF 

SOURCE=..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_md - Win32 Release"


"$(INTDIR)\mod_md.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_md.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "NDEBUG" /d BIN_NAME="mod_md.so" /d LONG_NAME="md_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_md - Win32 Debug"


"$(INTDIR)\mod_md.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_md.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "_DEBUG" /d BIN_NAME="mod_md.so" /d LONG_NAME="md_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=./md_acme.c

"$(INTDIR)\md_acme.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_acme_acct.c

"$(INTDIR)\md_acme_acct.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_acme_authz.c

"$(INTDIR)\md_acme_authz.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_acme_drive.c

"$(INTDIR)\md_acme_drive.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_core.c

"$(INTDIR)\md_core.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_crypt.c

"$(INTDIR)\md_crypt.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_curl.c

"$(INTDIR)\md_curl.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_http.c

"$(INTDIR)\md_http.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_json.c

"$(INTDIR)\md_json.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_jws.c

"$(INTDIR)\md_jws.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_log.c

"$(INTDIR)\md_log.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_reg.c

"$(INTDIR)\md_reg.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_store.c

"$(INTDIR)\md_store.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_store_fs.c

"$(INTDIR)\md_store_fs.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./md_util.c

"$(INTDIR)\md_util.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./mod_md.c

"$(INTDIR)\mod_md.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./mod_md_config.c

"$(INTDIR)\mod_md_config.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./mod_md_os.c

"$(INTDIR)\mod_md_os.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

