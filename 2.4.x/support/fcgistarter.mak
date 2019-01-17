# Microsoft Developer Studio Generated NMAKE File, Based on fcgistarter.dsp
!IF "$(CFG)" == ""
CFG=fcgistarter - Win32 Debug
!MESSAGE No configuration specified. Defaulting to fcgistarter - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "fcgistarter - Win32 Release" && "$(CFG)" != "fcgistarter - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "fcgistarter.mak" CFG="fcgistarter - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "fcgistarter - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "fcgistarter - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "fcgistarter - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\fcgistarter.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Release" "apr - Win32 Release" "$(OUTDIR)\fcgistarter.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 ReleaseCLEAN" "aprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\fcgistarter.obj"
	-@erase "$(INTDIR)\fcgistarter.res"
	-@erase "$(INTDIR)\fcgistarter_src.idb"
	-@erase "$(INTDIR)\fcgistarter_src.pdb"
	-@erase "$(OUTDIR)\fcgistarter.exe"
	-@erase "$(OUTDIR)\fcgistarter.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\fcgistarter_src" /FD /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\fcgistarter.res" /i "../include" /i "../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="fcgistarter.exe" /d LONG_NAME="Apache fcgi command line utility" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\fcgistarter.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib shell32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\fcgistarter.pdb" /debug /out:"$(OUTDIR)\fcgistarter.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\fcgistarter.obj" \
	"$(INTDIR)\fcgistarter.res" \
	"..\srclib\apr\LibR\apr-1.lib" \
	"..\srclib\apr-util\LibR\aprutil-1.lib"

"$(OUTDIR)\fcgistarter.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\fcgistarter.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\fcgistarter.exe"
   if exist .\Release\fcgistarter.exe.manifest mt.exe -manifest .\Release\fcgistarter.exe.manifest -outputresource:.\Release\fcgistarter.exe;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "fcgistarter - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\fcgistarter.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Debug" "apr - Win32 Debug" "$(OUTDIR)\fcgistarter.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 DebugCLEAN" "aprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\fcgistarter.obj"
	-@erase "$(INTDIR)\fcgistarter.res"
	-@erase "$(INTDIR)\fcgistarter_src.idb"
	-@erase "$(INTDIR)\fcgistarter_src.pdb"
	-@erase "$(OUTDIR)\fcgistarter.exe"
	-@erase "$(OUTDIR)\fcgistarter.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\fcgistarter_src" /FD /EHsc /c 

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

RSC=rc.exe
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\fcgistarter.res" /i "../include" /i "../srclib/apr/include" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="fcgistarter.exe" /d LONG_NAME="Apache fcgi command line utility" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\fcgistarter.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib shell32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\fcgistarter.pdb" /debug /out:"$(OUTDIR)\fcgistarter.exe" 
LINK32_OBJS= \
	"$(INTDIR)\fcgistarter.obj" \
	"$(INTDIR)\fcgistarter.res" \
	"..\srclib\apr\LibD\apr-1.lib" \
	"..\srclib\apr-util\LibD\aprutil-1.lib"

"$(OUTDIR)\fcgistarter.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\fcgistarter.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\fcgistarter.exe"
   if exist .\Debug\fcgistarter.exe.manifest mt.exe -manifest .\Debug\fcgistarter.exe.manifest -outputresource:.\Debug\fcgistarter.exe;2
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("fcgistarter.dep")
!INCLUDE "fcgistarter.dep"
!ELSE 
!MESSAGE Warning: cannot find "fcgistarter.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "fcgistarter - Win32 Release" || "$(CFG)" == "fcgistarter - Win32 Debug"

!IF  "$(CFG)" == "fcgistarter - Win32 Release"

"apr - Win32 Release" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" 
   cd "..\..\support"

"apr - Win32 ReleaseCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "fcgistarter - Win32 Debug"

"apr - Win32 Debug" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" 
   cd "..\..\support"

"apr - Win32 DebugCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support"

!ENDIF 

!IF  "$(CFG)" == "fcgistarter - Win32 Release"

"aprutil - Win32 Release" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" 
   cd "..\..\support"

"aprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "fcgistarter - Win32 Debug"

"aprutil - Win32 Debug" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" 
   cd "..\..\support"

"aprutil - Win32 DebugCLEAN" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support"

!ENDIF 

SOURCE=.\fcgistarter.c

"$(INTDIR)\fcgistarter.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=..\build\win32\httpd.rc

!IF  "$(CFG)" == "fcgistarter - Win32 Release"


"$(INTDIR)\fcgistarter.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\fcgistarter.res" /i "../include" /i "../srclib/apr/include" /i "../build\win32" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="fcgistarter.exe" /d LONG_NAME="Apache fcgi command line utility" $(SOURCE)


!ELSEIF  "$(CFG)" == "fcgistarter - Win32 Debug"


"$(INTDIR)\fcgistarter.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\fcgistarter.res" /i "../include" /i "../srclib/apr/include" /i "../build\win32" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="fcgistarter.exe" /d LONG_NAME="Apache fcgi command line utility" $(SOURCE)


!ENDIF 


!ENDIF 

