# Microsoft Developer Studio Generated NMAKE File, Based on gen_uri_delims.dsp
!IF "$(CFG)" == ""
CFG=gen_uri_delims - Win32 Debug
!MESSAGE No configuration specified. Defaulting to gen_uri_delims - Win32\
 Debug.
!ENDIF 

!IF "$(CFG)" != "gen_uri_delims - Win32 Release" && "$(CFG)" !=\
 "gen_uri_delims - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_uri_delims.mak" CFG="gen_uri_delims - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_uri_delims - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "gen_uri_delims - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "gen_uri_delims - Win32 Release"

OUTDIR=.
INTDIR=.\gen_uri_delims_R
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_uri_delims.exe"

!ELSE 

ALL : "$(OUTDIR)\gen_uri_delims.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\gen_uri_delims.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\gen_uri_delims.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D\
 "_MBCS" /Fp"$(INTDIR)\gen_uri_delims.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\gen_uri_delims_R/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_uri_delims.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\gen_uri_delims.pdb" /machine:I386\
 /out:"$(OUTDIR)\gen_uri_delims.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_uri_delims.obj"

"$(OUTDIR)\gen_uri_delims.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
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
INTDIR=.\gen_uri_delims_D
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_uri_delims.exe"

!ELSE 

ALL : "$(OUTDIR)\gen_uri_delims.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\gen_uri_delims.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\gen_uri_delims.exe"
	-@erase "$(OUTDIR)\gen_uri_delims.ilk"
	-@erase "$(OUTDIR)\gen_uri_delims.pdb"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE"\
 /D "_MBCS" /Fp"$(INTDIR)\gen_uri_delims.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\gen_uri_delims_D/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_uri_delims.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\gen_uri_delims.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\gen_uri_delims.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\gen_uri_delims.obj"

"$(OUTDIR)\gen_uri_delims.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
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

.c{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_OBJS)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<


!IF "$(CFG)" == "gen_uri_delims - Win32 Release" || "$(CFG)" ==\
 "gen_uri_delims - Win32 Debug"
SOURCE=.\gen_uri_delims.c

"$(INTDIR)\gen_uri_delims.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

