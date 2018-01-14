# Microsoft Developer Studio Generated NMAKE File, Based on ApacheMonitor.dsp
!IF "$(CFG)" == ""
CFG=ApacheMonitor - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ApacheMonitor - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheMonitor - Win32 Release" && "$(CFG)" != "ApacheMonitor - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheMonitor.mak" CFG="ApacheMonitor - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheMonitor - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "ApacheMonitor - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheMonitor.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Release" "apr - Win32 Release" "$(OUTDIR)\ApacheMonitor.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 ReleaseCLEAN" "aprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(INTDIR)\ApacheMonitor_src.idb"
	-@erase "$(INTDIR)\ApacheMonitor_src.pdb"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"
	-@erase "$(OUTDIR)\ApacheMonitor.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "../../include" /I "../../srclib/apr/include" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheMonitor_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ApacheMonitor.res" /i "../../include" /i "../../srclib/apr/include" /d "NDEBUG" /d "APP_FILE" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows /incremental:no /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /debug /out:"$(OUTDIR)\ApacheMonitor.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\ApacheMonitor.obj" \
	"$(INTDIR)\ApacheMonitor.res" \
	"..\..\srclib\apr\LibR\apr-1.lib" \
	"..\..\srclib\apr-util\LibR\aprutil-1.lib"

"$(OUTDIR)\ApacheMonitor.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Release\ApacheMonitor.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\ApacheMonitor.exe"
   if exist .\Release\ApacheMonitor.exe.manifest mt.exe -manifest .\Release\ApacheMonitor.exe.manifest -outputresource:.\Release\ApacheMonitor.exe;1
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "ApacheMonitor - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheMonitor.exe" "$(DS_POSTBUILD_DEP)"

!ELSE 

ALL : "aprutil - Win32 Debug" "apr - Win32 Debug" "$(OUTDIR)\ApacheMonitor.exe" "$(DS_POSTBUILD_DEP)"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 DebugCLEAN" "aprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(INTDIR)\ApacheMonitor_src.idb"
	-@erase "$(INTDIR)\ApacheMonitor_src.pdb"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"
	-@erase "$(OUTDIR)\ApacheMonitor.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /Zi /Od /I "../../include" /I "../../srclib/apr/include" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheMonitor_src" /FD /EHsc /c 

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
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ApacheMonitor.res" /i "../../include" /i "../../srclib/apr/include" /d "_DEBUG" /d "APP_FILE" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib wtsapi32.lib /nologo /subsystem:windows /incremental:no /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /debug /out:"$(OUTDIR)\ApacheMonitor.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ApacheMonitor.obj" \
	"$(INTDIR)\ApacheMonitor.res" \
	"..\..\srclib\apr\LibD\apr-1.lib" \
	"..\..\srclib\apr-util\LibD\aprutil-1.lib"

"$(OUTDIR)\ApacheMonitor.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

TargetPath=.\Debug\ApacheMonitor.exe
SOURCE="$(InputPath)"
PostBuild_Desc=Embed .manifest
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

"$(DS_POSTBUILD_DEP)" : "$(OUTDIR)\ApacheMonitor.exe"
   if exist .\Debug\ApacheMonitor.exe.manifest mt.exe -manifest .\Debug\ApacheMonitor.exe.manifest -outputresource:.\Debug\ApacheMonitor.exe;1
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("ApacheMonitor.dep")
!INCLUDE "ApacheMonitor.dep"
!ELSE 
!MESSAGE Warning: cannot find "ApacheMonitor.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "ApacheMonitor - Win32 Release" || "$(CFG)" == "ApacheMonitor - Win32 Debug"

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

"apr - Win32 Release" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" 
   cd "..\..\support\win32"

"apr - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support\win32"

!ELSEIF  "$(CFG)" == "ApacheMonitor - Win32 Debug"

"apr - Win32 Debug" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" 
   cd "..\..\support\win32"

"apr - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support\win32"

!ENDIF 

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

"aprutil - Win32 Release" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" 
   cd "..\..\support\win32"

"aprutil - Win32 ReleaseCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\support\win32"

!ELSEIF  "$(CFG)" == "ApacheMonitor - Win32 Debug"

"aprutil - Win32 Debug" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" 
   cd "..\..\support\win32"

"aprutil - Win32 DebugCLEAN" : 
   cd ".\..\..\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\support\win32"

!ENDIF 

SOURCE=.\ApacheMonitor.c

"$(INTDIR)\ApacheMonitor.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ApacheMonitor.rc

"$(INTDIR)\ApacheMonitor.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE)



!ENDIF 

