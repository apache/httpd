# Microsoft Developer Studio Generated NMAKE File, Based on mod_brotli.dsp
!IF "$(CFG)" == ""
CFG=mod_brotli - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_brotli - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_brotli - Win32 Release" && "$(CFG)" != "mod_brotli - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_brotli.mak" CFG="mod_brotli - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_brotli - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_brotli - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_brotli - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_brotli.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_brotli.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_brotli.obj"
	-@erase "$(INTDIR)\mod_brotli.res"
	-@erase "$(INTDIR)\mod_brotli_src.idb"
	-@erase "$(INTDIR)\mod_brotli_src.pdb"
	-@erase "$(OUTDIR)\mod_brotli.exp"
	-@erase "$(OUTDIR)\mod_brotli.lib"
	-@erase "$(OUTDIR)\mod_brotli.pdb"
	-@erase "$(OUTDIR)\mod_brotli.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/brotli/include" /I "../../srclib/brotli/c/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_brotli_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_brotli.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_brotli.so" /d LONG_NAME="brotli_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_brotli.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib brotlicommon.lib brotlienc.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_brotli.pdb" /libpath:"../../srclib/brotli" /debug /out:"$(OUTDIR)\mod_brotli.so" /implib:"$(OUTDIR)\mod_brotli.lib" /base:@..\..\os\win32\BaseAddr.ref,mod_brotli.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_brotli.obj" \
	"$(INTDIR)\mod_brotli.res" \
	"..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\Release\libhttpd.lib"

"$(OUTDIR)\mod_brotli.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_brotli.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_brotli.so"
   if exist .\Release\mod_brotli.so.manifest mt.exe -manifest .\Release\mod_brotli.so.manifest -outputresource:.\Release\mod_brotli.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_brotli - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_brotli.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_brotli.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_brotli.obj"
	-@erase "$(INTDIR)\mod_brotli.res"
	-@erase "$(INTDIR)\mod_brotli_src.idb"
	-@erase "$(INTDIR)\mod_brotli_src.pdb"
	-@erase "$(OUTDIR)\mod_brotli.exp"
	-@erase "$(OUTDIR)\mod_brotli.lib"
	-@erase "$(OUTDIR)\mod_brotli.pdb"
	-@erase "$(OUTDIR)\mod_brotli.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/brotli/include" /I "../../srclib/brotli/c/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "HAVE_ZUTIL_H" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_brotli_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_brotli.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_brotli.so" /d LONG_NAME="brotli_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_brotli.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib brotlicommon.lib brotlienc.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_brotli.pdb" /debug /libpath:"../../srclib/brotli" /out:"$(OUTDIR)\mod_brotli.so" /implib:"$(OUTDIR)\mod_brotli.lib" /libpath:"..\..\srclib\brotli\Debug\bin" /base:@..\..\os\win32\BaseAddr.ref,mod_brotli.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_brotli.obj" \
	"$(INTDIR)\mod_brotli.res" \
	"..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\Debug\libhttpd.lib"

"$(OUTDIR)\mod_brotli.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_brotli.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_brotli.so"
   if exist .\Debug\mod_brotli.so.manifest mt.exe -manifest .\Debug\mod_brotli.so.manifest -outputresource:.\Debug\mod_brotli.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_brotli.dep")
!INCLUDE "mod_brotli.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_brotli.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_brotli - Win32 Release" || "$(CFG)" == "mod_brotli - Win32 Debug"

!IF  "$(CFG)" == "mod_brotli - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\filters"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\filters"

!ELSEIF  "$(CFG)" == "mod_brotli - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\filters"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\filters"

!ENDIF 

!IF  "$(CFG)" == "mod_brotli - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\filters"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\filters"

!ELSEIF  "$(CFG)" == "mod_brotli - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\filters"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\filters"

!ENDIF 

!IF  "$(CFG)" == "mod_brotli - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\filters"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\filters"

!ELSEIF  "$(CFG)" == "mod_brotli - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\filters"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\filters"

!ENDIF 

SOURCE=..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_brotli - Win32 Release"


"$(INTDIR)\mod_brotli.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_brotli.res" /i "../../include" /i "../../srclib/apr/include" /i "\build4\httpd-2.4.23\build\win32" /d "NDEBUG" /d BIN_NAME="mod_brotli.so" /d LONG_NAME="brotli_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_brotli - Win32 Debug"


"$(INTDIR)\mod_brotli.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_brotli.res" /i "../../include" /i "../../srclib/apr/include" /i "\build4\httpd-2.4.23\build\win32" /d "_DEBUG" /d BIN_NAME="mod_brotli.so" /d LONG_NAME="brotli_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=.\mod_brotli.c

"$(INTDIR)\mod_brotli.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

