# Microsoft Developer Studio Generated NMAKE File, Based on gen_uri_delims.dsp
!IF "$(CFG)" == ""
CFG=gen_uri_delims - Win32 Debug
!MESSAGE No configuration specified. Defaulting to gen_uri_delims - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "gen_uri_delims - Win32 Release" && "$(CFG)" != "gen_uri_delims - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_uri_delims - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "gen_uri_delims - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "gen_uri_delims - Win32 Release"

OUTDIR=.
INTDIR=.\Release
# Begin Custom Macros
OutDir=.
# End Custom Macros

ALL : "$(OUTDIR)\gen_uri_delims.exe"


CLEAN :
	-@erase "$(INTDIR)\gen_uri_delims.idb"
	-@erase "$(INTDIR)\gen_uri_delims.obj"
	-@erase "$(OUTDIR)\gen_uri_delims.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\gen_uri_delims" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_uri_delims.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Release\gen_uri_delims.pdb" /machine:I386 /out:"$(OUTDIR)\gen_uri_delims.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_uri_delims.obj"

"$(OUTDIR)\gen_uri_delims.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE="$(InputPath)"
PostBuild_Desc=Create uri_delims.h
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.
# End Custom Macros

$(DS_POSTBUILD_DEP) : "$(OUTDIR)\gen_uri_delims.exe"
   .\gen_uri_delims > uri_delims.h
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "gen_uri_delims - Win32 Debug"

OUTDIR=.
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.
# End Custom Macros

ALL : "$(OUTDIR)\gen_uri_delims.exe"


CLEAN :
	-@erase "$(INTDIR)\gen_uri_delims.idb"
	-@erase "$(INTDIR)\gen_uri_delims.obj"
	-@erase "$(OUTDIR)\Debug\gen_uri_delims.pdb"
	-@erase "$(OUTDIR)\gen_uri_delims.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\gen_uri_delims" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_uri_delims.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Debug\gen_uri_delims.pdb" /debug /machine:I386 /out:"$(OUTDIR)\gen_uri_delims.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_uri_delims.obj"

"$(OUTDIR)\gen_uri_delims.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE="$(InputPath)"
PostBuild_Desc=Create uri_delims.h
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.
# End Custom Macros

$(DS_POSTBUILD_DEP) : "$(OUTDIR)\gen_uri_delims.exe"
   .\gen_uri_delims > uri_delims.h
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("gen_uri_delims.dep")
!INCLUDE "gen_uri_delims.dep"
!ELSE 
!MESSAGE Warning: cannot find "gen_uri_delims.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "gen_uri_delims - Win32 Release" || "$(CFG)" == "gen_uri_delims - Win32 Debug"
SOURCE=.\gen_uri_delims.c

"$(INTDIR)\gen_uri_delims.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

