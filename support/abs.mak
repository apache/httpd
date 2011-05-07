# Microsoft Developer Studio Generated NMAKE File, Based on abs.dsp
!IF "$(CFG)" == ""
CFG=abs - Win32 Debug
!MESSAGE No configuration specified. Defaulting to abs - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "abs - Win32 Release" && "$(CFG)" != "abs - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "abs.mak" CFG="abs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "abs - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "abs - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "abs - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\abs.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Release" "apr - Win32 Release" "$(OUTDIR)\abs.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 ReleaseCLEAN" "aprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ab.res"
	-@erase "$(INTDIR)\abs.obj"
	-@erase "$(INTDIR)\abs_src.idb"
	-@erase "$(INTDIR)\abs_src.pdb"
	-@erase "$(OUTDIR)\abs.exe"
	-@erase "$(OUTDIR)\abs.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\abs_src" /FD /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ab.res" /i "../include" /i "../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\abs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\abs.pdb" /debug /out:"$(OUTDIR)\abs.exe" /libpath:"../srclib/openssl/out32dll" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\abs.obj" \
	"$(INTDIR)\ab.res" \
	"..\srclib\apr\LibR\apr-1.lib" \
	"..\srclib\apr-util\LibR\aprutil-1.lib"

"$(OUTDIR)\abs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\abs.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\abs.exe"
   if exist .\Release\abs.exe.manifest mt.exe -manifest .\Release\abs.exe.manifest -outputresource:.\Release\abs.exe;1
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\abs.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Debug" "apr - Win32 Debug" "$(OUTDIR)\abs.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 DebugCLEAN" "aprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ab.res"
	-@erase "$(INTDIR)\abs.obj"
	-@erase "$(INTDIR)\abs_src.idb"
	-@erase "$(INTDIR)\abs_src.pdb"
	-@erase "$(OUTDIR)\abs.exe"
	-@erase "$(OUTDIR)\abs.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\abs_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ab.res" /i "../include" /i "../srclib/apr/include" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\abs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib shell32.lib ssleay32.lib libeay32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\abs.pdb" /debug /out:"$(OUTDIR)\abs.exe" /libpath:"../srclib/openssl/out32dll" 
LINK32_OBJS= \
	"$(INTDIR)\abs.obj" \
	"$(INTDIR)\ab.res" \
	"..\srclib\apr\LibD\apr-1.lib" \
	"..\srclib\apr-util\LibD\aprutil-1.lib"

"$(OUTDIR)\abs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\abs.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\abs.exe"
   if exist .\Debug\abs.exe.manifest mt.exe -manifest .\Debug\abs.exe.manifest -outputresource:.\Debug\abs.exe;1
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("abs.dep")
!INCLUDE "abs.dep"
!ELSE 
!MESSAGE Warning: cannot find "abs.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "abs - Win32 Release" || "$(CFG)" == "abs - Win32 Debug"

!IF  "$(CFG)" == "abs - Win32 Release"

"apr - Win32 Release" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" 
   cd "..\..\support"

"apr - Win32 ReleaseCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

"apr - Win32 Debug" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" 
   cd "..\..\support"

"apr - Win32 DebugCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support"

!ENDIF 

!IF  "$(CFG)" == "abs - Win32 Release"

"aprutil - Win32 Release" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" 
   cd "..\..\support"

"aprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support"

!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

"aprutil - Win32 Debug" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" 
   cd "..\..\support"

"aprutil - Win32 DebugCLEAN" : 
   cd ".\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support"

!ENDIF 

SOURCE=.\ab.c

!IF  "$(CFG)" == "abs - Win32 Release"

CPP_SWITCHES=/nologo /MD /W3 /Zi /O2 /Oy- /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fo"$(INTDIR)\abs.obj" /Fd"$(INTDIR)\abs_src" /FD /c 

"$(INTDIR)\abs.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ELSEIF  "$(CFG)" == "abs - Win32 Debug"

CPP_SWITCHES=/nologo /MDd /W3 /Zi /Od /I "../srclib/apr/include" /I "../srclib/apr-util/include" /I "../include" /I "../srclib/openssl/inc32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /D "HAVE_OPENSSL" /D "WIN32_LEAN_AND_MEAN" /D "NO_IDEA" /D "NO_RC5" /D "NO_MDC2" /D "OPENSSL_NO_IDEA" /D "OPENSSL_NO_RC5" /D "OPENSSL_NO_MDC2" /Fo"$(INTDIR)\abs.obj" /Fd"$(INTDIR)\abs_src" /FD /EHsc /c 

"$(INTDIR)\abs.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) @<<
  $(CPP_SWITCHES) $(SOURCE)
<<


!ENDIF 

SOURCE=..\build\win32\httpd.rc

!IF  "$(CFG)" == "abs - Win32 Release"


"$(INTDIR)\ab.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\ab.res" /i "../include" /i "../srclib/apr/include" /i ".\..\build\win32" /d "NDEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility" $(SOURCE)


!ELSEIF  "$(CFG)" == "abs - Win32 Debug"


"$(INTDIR)\ab.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) /l 0x409 /fo"$(INTDIR)\ab.res" /i "../include" /i "../srclib/apr/include" /i ".\..\build\win32" /d "_DEBUG" /d "APP_FILE" /d BIN_NAME="ab.exe" /d LONG_NAME="ApacheBench/SSL command line utility" $(SOURCE)


!ENDIF 


!ENDIF 

