# Microsoft Developer Studio Generated NMAKE File, Based on mod_http2.dsp
!IF "$(CFG)" == ""
CFG=mod_http2 - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_http2 - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_http2 - Win32 Release" && "$(CFG)" != "mod_http2 - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_http2.mak" CFG="mod_http2 - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_http2 - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_http2 - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_http2 - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_http2.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_http2.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\h2_alt_svc.obj"
	-@erase "$(INTDIR)\h2_bucket_beam.obj"
	-@erase "$(INTDIR)\h2_bucket_eos.obj"
	-@erase "$(INTDIR)\h2_config.obj"
	-@erase "$(INTDIR)\h2_conn.obj"
	-@erase "$(INTDIR)\h2_conn_io.obj"
	-@erase "$(INTDIR)\h2_ctx.obj"
	-@erase "$(INTDIR)\h2_filter.obj"
	-@erase "$(INTDIR)\h2_from_h1.obj"
	-@erase "$(INTDIR)\h2_h2.obj"
	-@erase "$(INTDIR)\h2_headers.obj"
	-@erase "$(INTDIR)\h2_mplx.obj"
	-@erase "$(INTDIR)\h2_ngn_shed.obj"
	-@erase "$(INTDIR)\h2_push.obj"
	-@erase "$(INTDIR)\h2_request.obj"
	-@erase "$(INTDIR)\h2_session.obj"
	-@erase "$(INTDIR)\h2_stream.obj"
	-@erase "$(INTDIR)\h2_switch.obj"
	-@erase "$(INTDIR)\h2_task.obj"
	-@erase "$(INTDIR)\h2_util.obj"
	-@erase "$(INTDIR)\h2_workers.obj"
	-@erase "$(INTDIR)\mod_http2.obj"
	-@erase "$(INTDIR)\mod_http2.res"
	-@erase "$(INTDIR)\mod_http2_src.idb"
	-@erase "$(INTDIR)\mod_http2_src.pdb"
	-@erase "$(OUTDIR)\mod_http2.exp"
	-@erase "$(OUTDIR)\mod_http2.lib"
	-@erase "$(OUTDIR)\mod_http2.pdb"
	-@erase "$(OUTDIR)\mod_http2.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../ssl" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/nghttp2/lib/includes" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_http2_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_http2.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib nghttp2.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_http2.pdb" /debug /out:"$(OUTDIR)\mod_http2.so" /implib:"$(OUTDIR)\mod_http2.lib" /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\h2_alt_svc.obj" \
	"$(INTDIR)\h2_bucket_beam.obj" \
	"$(INTDIR)\h2_bucket_eos.obj" \
	"$(INTDIR)\h2_config.obj" \
	"$(INTDIR)\h2_conn.obj" \
	"$(INTDIR)\h2_conn_io.obj" \
	"$(INTDIR)\h2_ctx.obj" \
	"$(INTDIR)\h2_filter.obj" \
	"$(INTDIR)\h2_from_h1.obj" \
	"$(INTDIR)\h2_h2.obj" \
	"$(INTDIR)\h2_headers.obj" \
	"$(INTDIR)\h2_mplx.obj" \
	"$(INTDIR)\h2_ngn_shed.obj" \
	"$(INTDIR)\h2_push.obj" \
	"$(INTDIR)\h2_request.obj" \
	"$(INTDIR)\h2_session.obj" \
	"$(INTDIR)\h2_stream.obj" \
	"$(INTDIR)\h2_switch.obj" \
	"$(INTDIR)\h2_task.obj" \
	"$(INTDIR)\h2_util.obj" \
	"$(INTDIR)\h2_workers.obj" \
	"$(INTDIR)\mod_http2.obj" \
	"$(INTDIR)\mod_http2.res" \
	"..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\Release\libhttpd.lib"

"$(OUTDIR)\mod_http2.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_http2.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_http2.so"
   if exist .\Release\mod_http2.so.manifest mt.exe -manifest .\Release\mod_http2.so.manifest -outputresource:.\Release\mod_http2.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_http2.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_http2.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\h2_alt_svc.obj"
	-@erase "$(INTDIR)\h2_bucket_beam.obj"
	-@erase "$(INTDIR)\h2_bucket_eos.obj"
	-@erase "$(INTDIR)\h2_config.obj"
	-@erase "$(INTDIR)\h2_conn.obj"
	-@erase "$(INTDIR)\h2_conn_io.obj"
	-@erase "$(INTDIR)\h2_ctx.obj"
	-@erase "$(INTDIR)\h2_filter.obj"
	-@erase "$(INTDIR)\h2_from_h1.obj"
	-@erase "$(INTDIR)\h2_h2.obj"
	-@erase "$(INTDIR)\h2_headers.obj"
	-@erase "$(INTDIR)\h2_mplx.obj"
	-@erase "$(INTDIR)\h2_ngn_shed.obj"
	-@erase "$(INTDIR)\h2_push.obj"
	-@erase "$(INTDIR)\h2_request.obj"
	-@erase "$(INTDIR)\h2_session.obj"
	-@erase "$(INTDIR)\h2_stream.obj"
	-@erase "$(INTDIR)\h2_switch.obj"
	-@erase "$(INTDIR)\h2_task.obj"
	-@erase "$(INTDIR)\h2_util.obj"
	-@erase "$(INTDIR)\h2_workers.obj"
	-@erase "$(INTDIR)\mod_http2.obj"
	-@erase "$(INTDIR)\mod_http2.res"
	-@erase "$(INTDIR)\mod_http2_src.idb"
	-@erase "$(INTDIR)\mod_http2_src.pdb"
	-@erase "$(OUTDIR)\mod_http2.exp"
	-@erase "$(OUTDIR)\mod_http2.lib"
	-@erase "$(OUTDIR)\mod_http2.pdb"
	-@erase "$(OUTDIR)\mod_http2.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../ssl" /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/nghttp2/lib/includes" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D ssize_t=long /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_http2_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_http2.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib nghttp2d.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_http2.pdb" /debug /out:"$(OUTDIR)\mod_http2.so" /implib:"$(OUTDIR)\mod_http2.lib" /libpath:"..\..\srclib\nghttp2\lib\MSVC_obj" /base:@..\..\os\win32\BaseAddr.ref,mod_http2.so 
LINK32_OBJS= \
	"$(INTDIR)\h2_alt_svc.obj" \
	"$(INTDIR)\h2_bucket_beam.obj" \
	"$(INTDIR)\h2_bucket_eos.obj" \
	"$(INTDIR)\h2_config.obj" \
	"$(INTDIR)\h2_conn.obj" \
	"$(INTDIR)\h2_conn_io.obj" \
	"$(INTDIR)\h2_ctx.obj" \
	"$(INTDIR)\h2_filter.obj" \
	"$(INTDIR)\h2_from_h1.obj" \
	"$(INTDIR)\h2_h2.obj" \
	"$(INTDIR)\h2_headers.obj" \
	"$(INTDIR)\h2_mplx.obj" \
	"$(INTDIR)\h2_ngn_shed.obj" \
	"$(INTDIR)\h2_push.obj" \
	"$(INTDIR)\h2_request.obj" \
	"$(INTDIR)\h2_session.obj" \
	"$(INTDIR)\h2_stream.obj" \
	"$(INTDIR)\h2_switch.obj" \
	"$(INTDIR)\h2_task.obj" \
	"$(INTDIR)\h2_util.obj" \
	"$(INTDIR)\h2_workers.obj" \
	"$(INTDIR)\mod_http2.obj" \
	"$(INTDIR)\mod_http2.res" \
	"..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\Debug\libhttpd.lib"

"$(OUTDIR)\mod_http2.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_http2.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_http2.so"
   if exist .\Debug\mod_http2.so.manifest mt.exe -manifest .\Debug\mod_http2.so.manifest -outputresource:.\Debug\mod_http2.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_http2.dep")
!INCLUDE "mod_http2.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_http2.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_http2 - Win32 Release" || "$(CFG)" == "mod_http2 - Win32 Debug"

!IF  "$(CFG)" == "mod_http2 - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\http2"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\http2"

!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\http2"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\http2"

!ENDIF 

!IF  "$(CFG)" == "mod_http2 - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\http2"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\http2"

!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\http2"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\http2"

!ENDIF 

!IF  "$(CFG)" == "mod_http2 - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\http2"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\http2"

!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\http2"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\http2"

!ENDIF 

SOURCE=./h2_alt_svc.c

"$(INTDIR)\h2_alt_svc.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_bucket_beam.c

"$(INTDIR)/h2_bucket_beam.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_bucket_eos.c

"$(INTDIR)\h2_bucket_eos.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_config.c

"$(INTDIR)\h2_config.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_conn.c

"$(INTDIR)\h2_conn.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_conn_io.c

"$(INTDIR)\h2_conn_io.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_ctx.c

"$(INTDIR)\h2_ctx.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_filter.c

"$(INTDIR)\h2_filter.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_from_h1.c

"$(INTDIR)\h2_from_h1.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_h2.c

"$(INTDIR)\h2_h2.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_headers.c

"$(INTDIR)\h2_headers.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_mplx.c

"$(INTDIR)\h2_mplx.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_ngn_shed.c

"$(INTDIR)\h2_ngn_shed.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_push.c

"$(INTDIR)\h2_push.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_request.c

"$(INTDIR)\h2_request.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_session.c

"$(INTDIR)\h2_session.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_stream.c

"$(INTDIR)\h2_stream.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_switch.c

"$(INTDIR)\h2_switch.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_task.c

"$(INTDIR)\h2_task.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_util.c

"$(INTDIR)\h2_util.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=./h2_workers.c

"$(INTDIR)\h2_workers.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_http2 - Win32 Release"


"$(INTDIR)\mod_http2.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "NDEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_http2 - Win32 Debug"


"$(INTDIR)\mod_http2.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_http2.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "_DEBUG" /d BIN_NAME="mod_http2.so" /d LONG_NAME="http2_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=./mod_http2.c

"$(INTDIR)\mod_http2.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

