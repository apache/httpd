# Microsoft Developer Studio Generated NMAKE File, Based on mod_isapi.dsp
!IF "$(CFG)" == ""
CFG=mod_isapi - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_isapi - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_isapi - Win32 Release" && "$(CFG)" != "mod_isapi - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_isapi.mak" CFG="mod_isapi - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_isapi - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_isapi - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_isapi - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_isapi.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_isapi.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_isapi.obj"
	-@erase "$(INTDIR)\mod_isapi.res"
	-@erase "$(INTDIR)\mod_isapi_src.idb"
	-@erase "$(INTDIR)\mod_isapi_src.pdb"
	-@erase "$(OUTDIR)\mod_isapi.exp"
	-@erase "$(OUTDIR)\mod_isapi.lib"
	-@erase "$(OUTDIR)\mod_isapi.pdb"
	-@erase "$(OUTDIR)\mod_isapi.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../../include" /I "../../../srclib/apr/include" /I "../../../srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_isapi_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_isapi.res" /i "../../../include" /i "../../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_isapi.so" /d LONG_NAME="isapi_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_isapi.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_isapi.pdb" /debug /out:"$(OUTDIR)\mod_isapi.so" /implib:"$(OUTDIR)\mod_isapi.lib" /base:@..\..\..\os\win32\BaseAddr.ref,mod_isapi.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_isapi.obj" \
	"$(INTDIR)\mod_isapi.res" \
	"..\..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\..\Release\libhttpd.lib"

"$(OUTDIR)\mod_isapi.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_isapi.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_isapi.so"
   if exist .\Release\mod_isapi.so.manifest mt.exe -manifest .\Release\mod_isapi.so.manifest -outputresource:.\Release\mod_isapi.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_isapi - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_isapi.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_isapi.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_isapi.obj"
	-@erase "$(INTDIR)\mod_isapi.res"
	-@erase "$(INTDIR)\mod_isapi_src.idb"
	-@erase "$(INTDIR)\mod_isapi_src.pdb"
	-@erase "$(OUTDIR)\mod_isapi.exp"
	-@erase "$(OUTDIR)\mod_isapi.lib"
	-@erase "$(OUTDIR)\mod_isapi.pdb"
	-@erase "$(OUTDIR)\mod_isapi.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../../include" /I "../../../srclib/apr/include" /I "../../../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_isapi_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_isapi.res" /i "../../../include" /i "../../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_isapi.so" /d LONG_NAME="isapi_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_isapi.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_isapi.pdb" /debug /out:"$(OUTDIR)\mod_isapi.so" /implib:"$(OUTDIR)\mod_isapi.lib" /base:@..\..\..\os\win32\BaseAddr.ref,mod_isapi.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_isapi.obj" \
	"$(INTDIR)\mod_isapi.res" \
	"..\..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\..\Debug\libhttpd.lib"

"$(OUTDIR)\mod_isapi.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_isapi.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_isapi.so"
   if exist .\Debug\mod_isapi.so.manifest mt.exe -manifest .\Debug\mod_isapi.so.manifest -outputresource:.\Debug\mod_isapi.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_isapi.dep")
!INCLUDE "mod_isapi.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_isapi.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_isapi - Win32 Release" || "$(CFG)" == "mod_isapi - Win32 Debug"

!IF  "$(CFG)" == "mod_isapi - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\arch\win32"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\arch\win32"

!ELSEIF  "$(CFG)" == "mod_isapi - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\arch\win32"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\arch\win32"

!ENDIF 

!IF  "$(CFG)" == "mod_isapi - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\arch\win32"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\arch\win32"

!ELSEIF  "$(CFG)" == "mod_isapi - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\arch\win32"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\arch\win32"

!ENDIF 

!IF  "$(CFG)" == "mod_isapi - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\arch\win32"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\arch\win32"

!ELSEIF  "$(CFG)" == "mod_isapi - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\arch\win32"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\arch\win32"

!ENDIF 

SOURCE=..\..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_isapi - Win32 Release"


"$(INTDIR)\mod_isapi.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_isapi.res" /i "../../../include" /i "../../../srclib/apr/include" /i "../../../build\win32" /d "NDEBUG" /d BIN_NAME="mod_isapi.so" /d LONG_NAME="isapi_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_isapi - Win32 Debug"


"$(INTDIR)\mod_isapi.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_isapi.res" /i "../../../include" /i "../../../srclib/apr/include" /i "../../../build\win32" /d "_DEBUG" /d BIN_NAME="mod_isapi.so" /d LONG_NAME="isapi_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=.\mod_isapi.c

"$(INTDIR)\mod_isapi.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

