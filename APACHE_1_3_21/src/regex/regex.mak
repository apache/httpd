# Microsoft Developer Studio Generated NMAKE File, Based on regex.dsp
!IF "$(CFG)" == ""
CFG=regex - Win32 Debug
!MESSAGE No configuration specified. Defaulting to regex - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "regex - Win32 Release" && "$(CFG)" != "regex - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "regex.mak" CFG="regex - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "regex - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "regex - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "regex - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\regex.lib"

!ELSE 

ALL : "$(OUTDIR)\regex.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\regcomp.obj"
	-@erase "$(INTDIR)\regerror.obj"
	-@erase "$(INTDIR)\regex.idb"
	-@erase "$(INTDIR)\regexec.obj"
	-@erase "$(INTDIR)\regfree.obj"
	-@erase "$(OUTDIR)\regex.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\regex" /FD /c 
CPP_OBJS=.\LibR/
CPP_SBRS=.

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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\regex.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\regex.lib" 
LIB32_OBJS= \
	"$(INTDIR)\regcomp.obj" \
	"$(INTDIR)\regerror.obj" \
	"$(INTDIR)\regexec.obj" \
	"$(INTDIR)\regfree.obj"

"$(OUTDIR)\regex.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "regex - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\regex.lib"

!ELSE 

ALL : "$(OUTDIR)\regex.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\regcomp.obj"
	-@erase "$(INTDIR)\regerror.obj"
	-@erase "$(INTDIR)\regex.idb"
	-@erase "$(INTDIR)\regex.pdb"
	-@erase "$(INTDIR)\regexec.obj"
	-@erase "$(INTDIR)\regfree.obj"
	-@erase "$(OUTDIR)\regex.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\regex" /FD /c 
CPP_OBJS=.\LibD/
CPP_SBRS=.

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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\regex.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\regex.lib" 
LIB32_OBJS= \
	"$(INTDIR)\regcomp.obj" \
	"$(INTDIR)\regerror.obj" \
	"$(INTDIR)\regexec.obj" \
	"$(INTDIR)\regfree.obj"

"$(OUTDIR)\regex.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "regex - Win32 Release" || "$(CFG)" == "regex - Win32 Debug"
SOURCE=.\regcomp.c
DEP_CPP_REGCO=\
	"..\include\ap_ctype.h"\
	"..\include\hsregex.h"\
	".\cclass.h"\
	".\cname.h"\
	".\regcomp.ih"\
	".\regex2.h"\
	".\utils.h"\
	

"$(INTDIR)\regcomp.obj" : $(SOURCE) $(DEP_CPP_REGCO) "$(INTDIR)"


SOURCE=.\regerror.c
DEP_CPP_REGER=\
	"..\include\hsregex.h"\
	".\regerror.ih"\
	".\utils.h"\
	

"$(INTDIR)\regerror.obj" : $(SOURCE) $(DEP_CPP_REGER) "$(INTDIR)"


SOURCE=.\regexec.c
DEP_CPP_REGEX=\
	"..\include\ap_ctype.h"\
	"..\include\hsregex.h"\
	".\engine.c"\
	".\engine.ih"\
	".\regex2.h"\
	".\utils.h"\
	

"$(INTDIR)\regexec.obj" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"


SOURCE=.\regfree.c
DEP_CPP_REGFR=\
	"..\include\hsregex.h"\
	".\regex2.h"\
	".\utils.h"\
	

"$(INTDIR)\regfree.obj" : $(SOURCE) $(DEP_CPP_REGFR) "$(INTDIR)"



!ENDIF 

