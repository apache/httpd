# Microsoft Developer Studio Generated NMAKE File, Based on pcre.dsp
!IF "$(CFG)" == ""
CFG=pcre - Win32 Debug
!MESSAGE No configuration specified. Defaulting to pcre - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "pcre - Win32 Release" && "$(CFG)" != "pcre - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "pcre.mak" CFG="pcre - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "pcre - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "pcre - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe

!IF  "$(CFG)" == "pcre - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\pcre.lib"

!ELSE 

ALL : "dftables - Win32 Release" "$(OUTDIR)\pcre.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"dftables - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\get.obj"
	-@erase "$(INTDIR)\maketables.obj"
	-@erase "$(INTDIR)\pcre.idb"
	-@erase "$(INTDIR)\pcre.obj"
	-@erase "$(INTDIR)\study.obj"
	-@erase "$(OUTDIR)\pcre.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "_WIN32" /D "NDEBUG" /D "_WINDOWS" /D "STATIC"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\pcre" /FD /c 
CPP_OBJS=.\LibR/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\pcre.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\pcre.lib" 
LIB32_OBJS= \
	"$(INTDIR)\get.obj" \
	"$(INTDIR)\maketables.obj" \
	"$(INTDIR)\pcre.obj" \
	"$(INTDIR)\study.obj"

"$(OUTDIR)\pcre.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "pcre - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\pcre.lib"

!ELSE 

ALL : "dftables - Win32 Debug" "$(OUTDIR)\pcre.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"dftables - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\get.obj"
	-@erase "$(INTDIR)\maketables.obj"
	-@erase "$(INTDIR)\pcre.idb"
	-@erase "$(INTDIR)\pcre.obj"
	-@erase "$(INTDIR)\pcre.pdb"
	-@erase "$(INTDIR)\study.obj"
	-@erase "$(OUTDIR)\pcre.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_WIN32" /D "_DEBUG" /D "_WINDOWS" /D\
 "STATIC" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\pcre" /FD /c 
CPP_OBJS=.\LibD/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\pcre.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\pcre.lib" 
LIB32_OBJS= \
	"$(INTDIR)\get.obj" \
	"$(INTDIR)\maketables.obj" \
	"$(INTDIR)\pcre.obj" \
	"$(INTDIR)\study.obj"

"$(OUTDIR)\pcre.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

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


!IF "$(CFG)" == "pcre - Win32 Release" || "$(CFG)" == "pcre - Win32 Debug"
SOURCE=.\dftables.exe

!IF  "$(CFG)" == "pcre - Win32 Release"

InputPath=.\dftables.exe

".\chartables.c"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\dftables.exe >.\chartables.c 
	Echo Creating pcre chartables.c from dftables 
	

!ELSEIF  "$(CFG)" == "pcre - Win32 Debug"

InputPath=.\dftables.exe

".\chartables.c"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	.\dftables.exe >.\chartables.c 
	Echo Creating pcre chartables.c from dftables 
	

!ENDIF 

SOURCE=.\get.c
DEP_CPP_GET_C=\
	".\config.h"\
	".\internal.h"\
	".\pcre.h"\
	

"$(INTDIR)\get.obj" : $(SOURCE) $(DEP_CPP_GET_C) "$(INTDIR)" ".\config.h"\
 ".\pcre.h"


SOURCE=.\maketables.c
DEP_CPP_MAKET=\
	".\config.h"\
	".\internal.h"\
	".\pcre.h"\
	

"$(INTDIR)\maketables.obj" : $(SOURCE) $(DEP_CPP_MAKET) "$(INTDIR)"\
 ".\config.h" ".\pcre.h"


SOURCE=.\pcre.c
DEP_CPP_PCRE_=\
	".\chartables.c"\
	".\config.h"\
	".\internal.h"\
	".\pcre.h"\
	

"$(INTDIR)\pcre.obj" : $(SOURCE) $(DEP_CPP_PCRE_) "$(INTDIR)" ".\chartables.c"\
 ".\config.h" ".\pcre.h"


SOURCE=.\study.c
DEP_CPP_STUDY=\
	".\config.h"\
	".\internal.h"\
	".\pcre.h"\
	

"$(INTDIR)\study.obj" : $(SOURCE) $(DEP_CPP_STUDY) "$(INTDIR)" ".\config.h"\
 ".\pcre.h"


SOURCE=.\config.hw

!IF  "$(CFG)" == "pcre - Win32 Release"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ELSEIF  "$(CFG)" == "pcre - Win32 Debug"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ENDIF 

SOURCE=.\pcre.hw

!IF  "$(CFG)" == "pcre - Win32 Release"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ELSEIF  "$(CFG)" == "pcre - Win32 Debug"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ENDIF 

!IF  "$(CFG)" == "pcre - Win32 Release"

"dftables - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\dftables.mak" CFG="dftables - Win32 Release" 
   cd "."

"dftables - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\dftables.mak"\
 CFG="dftables - Win32 Release" RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "pcre - Win32 Debug"

"dftables - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\dftables.mak" CFG="dftables - Win32 Debug" 
   cd "."

"dftables - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\dftables.mak" CFG="dftables - Win32 Debug"\
 RECURSE=1 
   cd "."

!ENDIF 


!ENDIF 

