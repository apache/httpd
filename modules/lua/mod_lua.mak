# Microsoft Developer Studio Generated NMAKE File, Based on mod_lua.dsp
!IF "$(CFG)" == ""
CFG=mod_lua - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_lua - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_lua - Win32 Release" && "$(CFG)" != "mod_lua - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_lua.mak" CFG="mod_lua - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_lua - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_lua - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_lua - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_lua.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release" "libapr - Win32 Release" "$(OUTDIR)\mod_lua.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\lua_apr.obj"
	-@erase "$(INTDIR)\lua_config.obj"
	-@erase "$(INTDIR)\lua_dbd.obj"
	-@erase "$(INTDIR)\lua_passwd.obj"
	-@erase "$(INTDIR)\lua_request.obj"
	-@erase "$(INTDIR)\lua_vmprep.obj"
	-@erase "$(INTDIR)\mod_lua.obj"
	-@erase "$(INTDIR)\mod_lua.res"
	-@erase "$(INTDIR)\mod_lua_src.idb"
	-@erase "$(INTDIR)\mod_lua_src.pdb"
	-@erase "$(OUTDIR)\mod_lua.exp"
	-@erase "$(OUTDIR)\mod_lua.lib"
	-@erase "$(OUTDIR)\mod_lua.pdb"
	-@erase "$(OUTDIR)\mod_lua.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/lua/src" /I "../ssl" /I "../database" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_LUA_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_lua_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_lua.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d BIN_NAME="mod_lua.so" /d LONG_NAME="lua_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_lua.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib lua51.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_lua.pdb" /debug /out:"$(OUTDIR)\mod_lua.so" /implib:"$(OUTDIR)\mod_lua.lib" /libpath:"../../srclib/lua/src" /base:@..\..\os\win32\BaseAddr.ref,mod_lua.so /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\lua_apr.obj" \
	"$(INTDIR)\lua_config.obj" \
	"$(INTDIR)\lua_passwd.obj" \
	"$(INTDIR)\lua_request.obj" \
	"$(INTDIR)\lua_vmprep.obj" \
	"$(INTDIR)\mod_lua.obj" \
	"$(INTDIR)\lua_dbd.obj" \
	"$(INTDIR)\mod_lua.res" \
	"..\..\srclib\apr\Release\libapr-1.lib" \
	"..\..\srclib\apr-util\Release\libaprutil-1.lib" \
	"..\..\Release\libhttpd.lib"

"$(OUTDIR)\mod_lua.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\mod_lua.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_lua.so"
   if exist .\Release\mod_lua.so.manifest mt.exe -manifest .\Release\mod_lua.so.manifest -outputresource:.\Release\mod_lua.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "mod_lua - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_lua.so" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug" "libapr - Win32 Debug" "$(OUTDIR)\mod_lua.so" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\lua_apr.obj"
	-@erase "$(INTDIR)\lua_config.obj"
	-@erase "$(INTDIR)\lua_dbd.obj"
	-@erase "$(INTDIR)\lua_passwd.obj"
	-@erase "$(INTDIR)\lua_request.obj"
	-@erase "$(INTDIR)\lua_vmprep.obj"
	-@erase "$(INTDIR)\mod_lua.obj"
	-@erase "$(INTDIR)\mod_lua.res"
	-@erase "$(INTDIR)\mod_lua_src.idb"
	-@erase "$(INTDIR)\mod_lua_src.pdb"
	-@erase "$(OUTDIR)\mod_lua.exp"
	-@erase "$(OUTDIR)\mod_lua.lib"
	-@erase "$(OUTDIR)\mod_lua.pdb"
	-@erase "$(OUTDIR)\mod_lua.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/lua/src" /I "../ssl" /I "../database" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_LUA_DECLARE_EXPORT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_lua_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\mod_lua.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d BIN_NAME="mod_lua.so" /d LONG_NAME="lua_module for Apache" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_lua.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib ws2_32.lib lua51.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_lua.pdb" /debug /out:"$(OUTDIR)\mod_lua.so" /implib:"$(OUTDIR)\mod_lua.lib" /libpath:"../../srclib/lua/src" /base:@..\..\os\win32\BaseAddr.ref,mod_lua.so 
LINK32_OBJS= \
	"$(INTDIR)\lua_apr.obj" \
	"$(INTDIR)\lua_config.obj" \
	"$(INTDIR)\lua_passwd.obj" \
	"$(INTDIR)\lua_request.obj" \
	"$(INTDIR)\lua_vmprep.obj" \
	"$(INTDIR)\mod_lua.obj" \
	"$(INTDIR)\lua_dbd.obj" \
	"$(INTDIR)\mod_lua.res" \
	"..\..\srclib\apr\Debug\libapr-1.lib" \
	"..\..\srclib\apr-util\Debug\libaprutil-1.lib" \
	"..\..\Debug\libhttpd.lib"

"$(OUTDIR)\mod_lua.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\mod_lua.so
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\mod_lua.so"
   if exist .\Debug\mod_lua.so.manifest mt.exe -manifest .\Debug\mod_lua.so.manifest -outputresource:.\Debug\mod_lua.so;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_lua.dep")
!INCLUDE "mod_lua.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_lua.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_lua - Win32 Release" || "$(CFG)" == "mod_lua - Win32 Debug"

!IF  "$(CFG)" == "mod_lua - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\modules\lua"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\lua"

!ELSEIF  "$(CFG)" == "mod_lua - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\modules\lua"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\lua"

!ENDIF 

!IF  "$(CFG)" == "mod_lua - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" 
   cd "..\..\modules\lua"

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\modules\lua"

!ELSEIF  "$(CFG)" == "mod_lua - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\..\modules\lua"

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\modules\lua"

!ENDIF 

!IF  "$(CFG)" == "mod_lua - Win32 Release"

"libhttpd - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd ".\modules\lua"

"libhttpd - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" RECURSE=1 CLEAN 
   cd ".\modules\lua"

!ELSEIF  "$(CFG)" == "mod_lua - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd ".\modules\lua"

"libhttpd - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\modules\lua"

!ENDIF 

SOURCE=..\..\build\win32\httpd.rc

!IF  "$(CFG)" == "mod_lua - Win32 Release"


"$(INTDIR)\mod_lua.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_lua.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "NDEBUG" /d BIN_NAME="mod_lua.so" /d LONG_NAME="lua_module for Apache" $(SOURCE)


!ELSEIF  "$(CFG)" == "mod_lua - Win32 Debug"


"$(INTDIR)\mod_lua.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\mod_lua.res" /i "../../include" /i "../../srclib/apr/include" /i "../../build\win32" /d "_DEBUG" /d BIN_NAME="mod_lua.so" /d LONG_NAME="lua_module for Apache" $(SOURCE)


!ENDIF 

SOURCE=.\lua_apr.c

"$(INTDIR)\lua_apr.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lua_config.c

"$(INTDIR)\lua_config.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lua_dbd.c

"$(INTDIR)\lua_dbd.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lua_passwd.c

"$(INTDIR)\lua_passwd.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lua_request.c

"$(INTDIR)\lua_request.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\lua_vmprep.c

"$(INTDIR)\lua_vmprep.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\mod_lua.c

"$(INTDIR)\mod_lua.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

