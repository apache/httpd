# Microsoft Developer Studio Generated NMAKE File, Based on pcreposix.dsp
!IF "$(CFG)" == ""
CFG=pcreposix - Win32 Debug
!MESSAGE No configuration specified. Defaulting to pcreposix - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "pcreposix - Win32 Release" && "$(CFG)" !=\
 "pcreposix - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "pcreposix.mak" CFG="pcreposix - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "pcreposix - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "pcreposix - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe

!IF  "$(CFG)" == "pcreposix - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\pcreposix.lib"

!ELSE 

ALL : "pcre - Win32 Release" "$(OUTDIR)\pcreposix.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"pcre - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\pcreposix.idb"
	-@erase "$(INTDIR)\pcreposix.obj"
	-@erase "$(OUTDIR)\pcreposix.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "_WIN32" /D "NDEBUG" /D "_WINDOWS" /D "STATIC"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\pcreposix" /FD /c 
CPP_OBJS=.\LibR/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\pcreposix.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\pcreposix.lib" 
LIB32_OBJS= \
	"$(INTDIR)\pcreposix.obj" \
	"$(OUTDIR)\pcre.lib"

"$(OUTDIR)\pcreposix.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\pcreposix.lib"

!ELSE 

ALL : "pcre - Win32 Debug" "$(OUTDIR)\pcreposix.lib"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"pcre - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\pcreposix.idb"
	-@erase "$(INTDIR)\pcreposix.obj"
	-@erase "$(INTDIR)\pcreposix.pdb"
	-@erase "$(OUTDIR)\pcreposix.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_WIN32" /D "_DEBUG" /D "_WINDOWS" /D\
 "STATIC" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\pcreposix" /FD /c 
CPP_OBJS=.\LibD/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\pcreposix.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\pcreposix.lib" 
LIB32_OBJS= \
	"$(INTDIR)\pcreposix.obj" \
	"$(OUTDIR)\pcre.lib"

"$(OUTDIR)\pcreposix.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
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


!IF "$(CFG)" == "pcreposix - Win32 Release" || "$(CFG)" ==\
 "pcreposix - Win32 Debug"
SOURCE=.\pcreposix.c
DEP_CPP_PCREP=\
	".\config.h"\
	".\internal.h"\
	".\pcre.h"\
	".\pcreposix.h"\
	

"$(INTDIR)\pcreposix.obj" : $(SOURCE) $(DEP_CPP_PCREP) "$(INTDIR)" ".\config.h"\
 ".\pcre.h"


SOURCE=.\config.hw

!IF  "$(CFG)" == "pcreposix - Win32 Release"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ENDIF 

SOURCE=.\pcre.hw

!IF  "$(CFG)" == "pcreposix - Win32 Release"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ENDIF 

!IF  "$(CFG)" == "pcreposix - Win32 Release"

"pcre - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Release" 
   cd "."

"pcre - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Release"\
 RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "pcreposix - Win32 Debug"

"pcre - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Debug" 
   cd "."

"pcre - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Debug"\
 RECURSE=1 
   cd "."

!ENDIF 


!ENDIF 

