# Microsoft Developer Studio Generated NMAKE File, Based on gen_test_char.dsp
!IF "$(CFG)" == ""
CFG=gen_test_char - Win32 Debug
!MESSAGE No configuration specified. Defaulting to gen_test_char - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "gen_test_char - Win32 Release" && "$(CFG)" !=\
 "gen_test_char - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_test_char.mak" CFG="gen_test_char - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_test_char - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "gen_test_char - Win32 Debug" (based on\
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

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

OUTDIR=.
INTDIR=.\gen_test_char_R
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\gen_test_char.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\include" /D "WIN32" /D "NDEBUG" /D\
 "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\gen_test_char.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\gen_test_char_R/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\gen_test_char.pdb" /machine:I386\
 /out:"$(OUTDIR)\gen_test_char.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
PostBuild_Desc=Create test_char.h
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.
# End Custom Macros

$(DS_POSTBUILD_DEP) : "$(OUTDIR)\gen_test_char.exe"
   .\gen_test_char > test_char.h
	echo Helper for Post-build step > "$(DS_POSTBUILD_DEP)"

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

OUTDIR=.
INTDIR=.\gen_test_char_D
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\gen_test_char.exe"
	-@erase "$(OUTDIR)\gen_test_char.ilk"
	-@erase "$(OUTDIR)\gen_test_char.pdb"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\include" /D "WIN32" /D\
 "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\gen_test_char.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\gen_test_char_D/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\gen_test_char.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\gen_test_char.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

SOURCE=$(InputPath)
PostBuild_Desc=Create test_char.h
DS_POSTBUILD_DEP=$(INTDIR)\postbld.dep

ALL : $(DS_POSTBUILD_DEP)

# Begin Custom Macros
OutDir=.
# End Custom Macros

$(DS_POSTBUILD_DEP) : "$(OUTDIR)\gen_test_char.exe"
   .\gen_test_char > test_char.h
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


!IF "$(CFG)" == "gen_test_char - Win32 Release" || "$(CFG)" ==\
 "gen_test_char - Win32 Debug"
SOURCE=.\gen_test_char.c

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

DEP_CPP_GEN_T=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\buff.h"\
	"..\include\conf.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	

"$(INTDIR)\gen_test_char.obj" : $(SOURCE) $(DEP_CPP_GEN_T) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

DEP_CPP_GEN_T=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\buff.h"\
	"..\include\conf.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	

"$(INTDIR)\gen_test_char.obj" : $(SOURCE) $(DEP_CPP_GEN_T) "$(INTDIR)"


!ENDIF 


!ENDIF 

