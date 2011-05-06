# Microsoft Developer Studio Generated NMAKE File, Based on gen_test_char.dsp
!IF "$(CFG)" == ""
CFG=gen_test_char - Win32 Debug
!MESSAGE No configuration specified. Defaulting to gen_test_char - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "gen_test_char - Win32 Release" && "$(CFG)" != "gen_test_char - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_test_char.mak" CFG="gen_test_char - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_test_char - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "gen_test_char - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

OUTDIR=.
INTDIR=.\Release
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "libapr - Win32 Release" "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\gen_test_char.idb"
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(OUTDIR)\gen_test_char.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /I "..\srclib\apr\include" /I "..\srclib\apr-util\include" /I "..\os\win32" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\gen_test_char" /FD /c 

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
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Release\gen_test_char.pdb" /out:"$(OUTDIR)\gen_test_char.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj" \
	"..\srclib\apr\Release\libapr-1.lib"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

OUTDIR=.
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "libapr - Win32 Debug" "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\gen_test_char.idb"
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(OUTDIR)\Debug\gen_test_char.pdb"
	-@erase "$(OUTDIR)\gen_test_char.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Zi /Od /I "..\include" /I "..\srclib\apr\include" /I "..\srclib\apr-util\include" /I "..\os\win32" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\gen_test_char" /FD /EHsc /c 

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
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Debug\gen_test_char.pdb" /debug /out:"$(OUTDIR)\gen_test_char.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj" \
	"..\srclib\apr\Debug\libapr-1.lib"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("gen_test_char.dep")
!INCLUDE "gen_test_char.dep"
!ELSE 
!MESSAGE Warning: cannot find "gen_test_char.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "gen_test_char - Win32 Release" || "$(CFG)" == "gen_test_char - Win32 Debug"

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\..\server"

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" RECURSE=1 CLEAN 
   cd "..\..\server"

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\..\server"

"libapr - Win32 DebugCLEAN" : 
   cd ".\..\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" RECURSE=1 CLEAN 
   cd "..\..\server"

!ENDIF 

SOURCE=.\gen_test_char.c

"$(INTDIR)\gen_test_char.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

