# Microsoft Developer Studio Generated NMAKE File, Based on mod_dav_fs.dsp
!IF "$(CFG)" == ""
CFG=mod_dav_fs - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_dav_fs - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_dav_fs - Win32 Release" && "$(CFG)" != "mod_dav_fs - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_dav_fs.mak" CFG="mod_dav_fs - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_dav_fs - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_dav_fs - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
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
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav_fs.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "mod_dav - Win32 Release" "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_dav_fs.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" "mod_dav - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dbm.obj"
	-@erase "$(INTDIR)\lock.obj"
	-@erase "$(INTDIR)\mod_dav_fs.obj"
	-@erase "$(INTDIR)\mod_dav_fs.res"
	-@erase "$(INTDIR)\mod_dav_fs_src.idb"
	-@erase "$(INTDIR)\mod_dav_fs_src.pdb"
	-@erase "$(INTDIR)\repos.obj"
	-@erase "$(OUTDIR)\mod_dav_fs.exp"
	-@erase "$(OUTDIR)\mod_dav_fs.lib"
	-@erase "$(OUTDIR)\mod_dav_fs.pdb"
	-@erase "$(OUTDIR)\mod_dav_fs.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../../include" /I "../../../srclib/apr/include" /I "../../../srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav_fs_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_dav_fs.res" /i "../../../include" /i "../../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_dav_fs.so" /d LONG_NAME="dav_fs_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav_fs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_dav_fs.pdb" /debug /out:"$(OUTDIR)\mod_dav_fs.so" /implib:"$(OUTDIR)\mod_dav_fs.lib" /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav_fs.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\dbm.obj" \
	"$(INTDIR)\lock.obj" \
	"$(INTDIR)\mod_dav_fs.obj" \
	"$(INTDIR)\repos.obj" \
	"$(INTDIR)\mod_dav_fs.res" \
	"..\..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\..\Release\libhttpd.lib" \
	"..\main\Release\mod_dav.lib"

"$(OUTDIR)\mod_dav_fs.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_dav_fs.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_dav_fs.so"
   if exist .\Release\mod_dav_fs.so.manifest mt.exe -manifest .\Release\mod_dav_fs.so.manifest -outputresource:.\Release\mod_dav_fs.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_dav_fs.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "mod_dav - Win32 Debug" "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_dav_fs.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" "mod_dav - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\dbm.obj"
	-@erase "$(INTDIR)\lock.obj"
	-@erase "$(INTDIR)\mod_dav_fs.obj"
	-@erase "$(INTDIR)\mod_dav_fs.res"
	-@erase "$(INTDIR)\mod_dav_fs_src.idb"
	-@erase "$(INTDIR)\mod_dav_fs_src.pdb"
	-@erase "$(INTDIR)\repos.obj"
	-@erase "$(OUTDIR)\mod_dav_fs.exp"
	-@erase "$(OUTDIR)\mod_dav_fs.lib"
	-@erase "$(OUTDIR)\mod_dav_fs.pdb"
	-@erase "$(OUTDIR)\mod_dav_fs.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../../include" /I "../../../srclib/apr/include" /I "../../../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_dav_fs_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_dav_fs.res" /i "../../../include" /i "../../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_dav_fs.so" /d LONG_NAME="dav_fs_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_dav_fs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib mswsock.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_dav_fs.pdb" /debug /out:"$(OUTDIR)\mod_dav_fs.so" /implib:"$(OUTDIR)\mod_dav_fs.lib" /base:@..\..\..\os\win32\BaseAddr.ref,mod_dav_fs.so 
LINK32_OBJS= \
	"$(INTDIR)\dbm.obj" \
	"$(INTDIR)\lock.obj" \
	"$(INTDIR)\mod_dav_fs.obj" \
	"$(INTDIR)\repos.obj" \
	"$(INTDIR)\mod_dav_fs.res" \
	"..\..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\..\Debug\libhttpd.lib" \
	"..\main\Debug\mod_dav.lib"

"$(OUTDIR)\mod_dav_fs.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_dav_fs.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_dav_fs.so"
   if exist .\Debug\mod_dav_fs.so.manifest mt.exe -manifest .\Debug\mod_dav_fs.so.manifest -outputresource:.\Debug\mod_dav_fs.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_dav_fs.dep")
!INCLUDE "mod_dav_fs.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_dav_fs.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_dav_fs - Win32 Release" || "$(CFG)" == "mod_dav_fs - Win32 Debug"
SOURCE=.\dbm.c

"$(INTDIR)\dbm.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lock.c

"$(INTDIR)\lock.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_dav_fs.c

"$(INTDIR)\mod_dav_fs.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\repos.c

"$(INTDIR)\repos.obj" : $(SOURCE) "$(INTDIR)"


!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\dav\fs"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\dav\fs"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\dav\fs"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\dav\fs"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\dav\fs"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\dav\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\dav\fs"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\dav\fs"

!ENDIF 

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"

"mod_dav - Win32 Release" : 
   cd ".\..\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Release" 
   cd "..\fs"

"mod_dav - Win32 ReleaseCLEAN" : 
   cd ".\..\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Release" RECURSE=1 CLEAN 
   cd "..\fs"

!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"

"mod_dav - Win32 Debug" : 
   cd ".\..\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Debug" 
   cd "..\fs"

"mod_dav - Win32 DebugCLEAN" : 
   cd ".\..\main"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dav.mak" CFG="mod_dav - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\fs"

!ENDIF 

SOURCE=..\..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_dav_fs - Win32 Release"


"$(INTDIR)\mod_dav_fs.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_dav_fs.res" /i "../../../include" /i "../../../srclib/apr/include" /i "../../../build\win32" /d "NDEBUG" /d BIN_NAME="mod_dav_fs.so" /d LONG_NAME="dav_fs_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_dav_fs - Win32 Debug"


"$(INTDIR)\mod_dav_fs.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_dav_fs.res" /i "../../../include" /i "../../../srclib/apr/include" /i "../../../build\win32" /d "_DEBUG" /d BIN_NAME="mod_dav_fs.so" /d LONG_NAME="dav_fs_module for Apache" $(SOURCE)


!ENDIF 


!ENDIF 

