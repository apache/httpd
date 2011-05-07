# Microsoft Developer Studio Generated NMAKE File, Based on mod_authn_dbd.dsp
!IF "$(CFG)" == ""
CFG=mod_authn_dbd - Win32 Debug
!MESSAGE No configuration specified. Defaulting to mod_authn_dbd - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "mod_authn_dbd - Win32 Release" && "$(CFG)" != "mod_authn_dbd - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_authn_dbd.mak" CFG="mod_authn_dbd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_authn_dbd - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_authn_dbd - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_authn_dbd.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "mod_dbd - Win32 Release" "mod_auth_basic - Win32 Release" "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_authn_dbd.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" "mod_auth_basic - Win32 ReleaseCLEAN" "mod_dbd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_authn_dbd.obj"
	-@erase "$(INTDIR)\mod_authn_dbd.res"
	-@erase "$(INTDIR)\mod_authn_dbd_src.idb"
	-@erase "$(INTDIR)\mod_authn_dbd_src.pdb"
	-@erase "$(OUTDIR)\mod_authn_dbd.exp"
	-@erase "$(OUTDIR)\mod_authn_dbd.lib"
	-@erase "$(OUTDIR)\mod_authn_dbd.pdb"
	-@erase "$(OUTDIR)\mod_authn_dbd.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /D "DBD_DECLARE_EXPORT" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_authn_dbd_src" /FD /I ../database /c 

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
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL" 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_authn_dbd.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_authn_dbd.so" /d LONG_NAME="authn_dbd_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_authn_dbd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_authn_dbd.pdb" /debug /out:"$(OUTDIR)\mod_authn_dbd.so" /implib:"$(OUTDIR)\mod_authn_dbd.lib" /base:@..\..\os\win32\BaseAddr.ref,mod_authn_dbd.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_authn_dbd.obj" \
	"$(INTDIR)\mod_authn_dbd.res" \
	"..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\Release\libhttpd.lib" \
	"$(OUTDIR)\mod_auth_basic.lib" \
	"..\database\Release\mod_dbd.lib"

"$(OUTDIR)\mod_authn_dbd.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_authn_dbd.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_authn_dbd.so"
   if exist .\Release\mod_authn_dbd.so.manifest mt.exe -manifest .\Release\mod_authn_dbd.so.manifest -outputresource:.\Release\mod_authn_dbd.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_authn_dbd.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "mod_dbd - Win32 Debug" "mod_auth_basic - Win32 Debug" "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_authn_dbd.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" "mod_auth_basic - Win32 DebugCLEAN" "mod_dbd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_authn_dbd.obj"
	-@erase "$(INTDIR)\mod_authn_dbd.res"
	-@erase "$(INTDIR)\mod_authn_dbd_src.idb"
	-@erase "$(INTDIR)\mod_authn_dbd_src.pdb"
	-@erase "$(OUTDIR)\mod_authn_dbd.exp"
	-@erase "$(OUTDIR)\mod_authn_dbd.lib"
	-@erase "$(OUTDIR)\mod_authn_dbd.pdb"
	-@erase "$(OUTDIR)\mod_authn_dbd.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /D "DBD_DECLARE_EXPORT" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_authn_dbd_src" /FD /EHsc /I ../database /c 

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
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL" 
RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_authn_dbd.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_authn_dbd.so" /d LONG_NAME="authn_dbd_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_authn_dbd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_authn_dbd.pdb" /debug /out:"$(OUTDIR)\mod_authn_dbd.so" /implib:"$(OUTDIR)\mod_authn_dbd.lib" /base:@..\..\os\win32\BaseAddr.ref,mod_authn_dbd.so 
LINK32_OBJS= \
	"$(INTDIR)\mod_authn_dbd.obj" \
	"$(INTDIR)\mod_authn_dbd.res" \
	"..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\Debug\libhttpd.lib" \
	"$(OUTDIR)\mod_auth_basic.lib" \
	"..\database\Debug\mod_dbd.lib"

"$(OUTDIR)\mod_authn_dbd.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_authn_dbd.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_authn_dbd.so"
   if exist .\Debug\mod_authn_dbd.so.manifest mt.exe -manifest .\Debug\mod_authn_dbd.so.manifest -outputresource:.\Debug\mod_authn_dbd.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_authn_dbd.dep")
!INCLUDE "mod_authn_dbd.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_authn_dbd.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_authn_dbd - Win32 Release" || "$(CFG)" == "mod_authn_dbd - Win32 Debug"

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\aaa"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\aaa"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\aaa"

!ENDIF 

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\aaa"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\aaa"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\aaa"

!ENDIF 

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\aaa"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\aaa"

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\aaa"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\aaa"

!ENDIF 

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

"mod_auth_basic - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_auth_basic.mak" CFG="mod_auth_basic - Win32 Release" 
   cd "."

"mod_auth_basic - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_auth_basic.mak" CFG="mod_auth_basic - Win32 Release" RECURSE=1 CLEAN 
   cd "."

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

"mod_auth_basic - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_auth_basic.mak" CFG="mod_auth_basic - Win32 Debug" 
   cd "."

"mod_auth_basic - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_auth_basic.mak" CFG="mod_auth_basic - Win32 Debug" RECURSE=1 CLEAN 
   cd "."

!ENDIF 

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"

"mod_dbd - Win32 Release" : 
   cd ".\..\database"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dbd.mak" CFG="mod_dbd - Win32 Release" 
   cd "..\aaa"

"mod_dbd - Win32 ReleaseCLEAN" : 
   cd ".\..\database"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dbd.mak" CFG="mod_dbd - Win32 Release" RECURSE=1 CLEAN 
   cd "..\aaa"

!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"

"mod_dbd - Win32 Debug" : 
   cd ".\..\database"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dbd.mak" CFG="mod_dbd - Win32 Debug" 
   cd "..\aaa"

"mod_dbd - Win32 DebugCLEAN" : 
   cd ".\..\database"
   $(MAKE) /$(MAKEFLAGS) /F ".\mod_dbd.mak" CFG="mod_dbd - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\aaa"

!ENDIF 

SOURCE=..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_authn_dbd - Win32 Release"


"$(INTDIR)\mod_authn_dbd.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_authn_dbd.res" /i "../../include" /i "../../srclib/apr/include" /i ".\..\..\build\win32" /d "NDEBUG" /d BIN_NAME="mod_authn_dbd.so" /d LONG_NAME="authn_dbd_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_authn_dbd - Win32 Debug"


"$(INTDIR)\mod_authn_dbd.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_authn_dbd.res" /i "../../include" /i "../../srclib/apr/include" /i ".\..\..\build\win32" /d "_DEBUG" /d BIN_NAME="mod_authn_dbd.so" /d LONG_NAME="authn_dbd_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=.\mod_authn_dbd.c

"$(INTDIR)\mod_authn_dbd.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

