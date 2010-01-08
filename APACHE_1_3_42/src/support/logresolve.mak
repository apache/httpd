# Microsoft Developer Studio Generated NMAKE File, Based on logresolve.dsp
!IF "$(CFG)" == ""
CFG=logresolve - Win32 Debug
!MESSAGE No configuration specified. Defaulting to logresolve - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "logresolve - Win32 Release" && "$(CFG)" != "logresolve - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "logresolve.mak" CFG="logresolve - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "logresolve - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "logresolve - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "logresolve - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\logresolve.exe"


CLEAN :
	-@erase "$(INTDIR)\logresolve.obj"
	-@erase "$(INTDIR)\logresolve_src.idb"
	-@erase "$(INTDIR)\logresolve_src.pdb"
	-@erase "$(OUTDIR)\logresolve.exe"
	-@erase "$(OUTDIR)\logresolve.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "..\include" /I "..\os\win32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\logresolve_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\logresolve.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\logresolve.pdb" /debug /machine:I386 /out:"$(OUTDIR)\logresolve.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\logresolve.obj"

"$(OUTDIR)\logresolve.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "logresolve - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\logresolve.exe"


CLEAN :
	-@erase "$(INTDIR)\logresolve.obj"
	-@erase "$(INTDIR)\logresolve_src.idb"
	-@erase "$(INTDIR)\logresolve_src.pdb"
	-@erase "$(OUTDIR)\logresolve.exe"
	-@erase "$(OUTDIR)\logresolve.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\logresolve_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\logresolve.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=wsock32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\logresolve.pdb" /debug /machine:I386 /out:"$(OUTDIR)\logresolve.exe" 
LINK32_OBJS= \
	"$(INTDIR)\logresolve.obj"

"$(OUTDIR)\logresolve.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("logresolve.dep")
!INCLUDE "logresolve.dep"
!ELSE 
!MESSAGE Warning: cannot find "logresolve.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "logresolve - Win32 Release" || "$(CFG)" == "logresolve - Win32 Debug"
SOURCE=.\logresolve.c

"$(INTDIR)\logresolve.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

