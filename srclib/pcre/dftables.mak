# Microsoft Developer Studio Generated NMAKE File, Based on dftables.dsp
!IF "$(CFG)" == ""
CFG=dftables - Win32 Debug
!MESSAGE No configuration specified. Defaulting to dftables - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "dftables - Win32 Release" && "$(CFG)" !=\
 "dftables - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "dftables.mak" CFG="dftables - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "dftables - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "dftables - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "dftables - Win32 Release"

OUTDIR=.
INTDIR=.\Release
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\dftables.exe"

!ELSE 

ALL : "$(OUTDIR)\dftables.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dftables.idb"
	-@erase "$(INTDIR)\dftables.obj"
	-@erase "$(OUTDIR)\dftables.exe"
	-@erase "$(OUTDIR)\Release\dftables.map"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /D "_WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\dftables" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\dftables.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Release\dftables.pdb" /map:"$(INTDIR)\dftables.map"\
 /machine:I386 /out:"$(OUTDIR)\dftables.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dftables.obj"

"$(OUTDIR)\dftables.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

OUTDIR=.
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\dftables.exe"

!ELSE 

ALL : "$(OUTDIR)\dftables.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dftables.idb"
	-@erase "$(INTDIR)\dftables.obj"
	-@erase "$(OUTDIR)\Debug\dftables.map"
	-@erase "$(OUTDIR)\Debug\dftables.pdb"
	-@erase "$(OUTDIR)\dftables.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_WIN32" /D "_DEBUG" /D "_CONSOLE" /D\
 "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\dftables" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\dftables.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Debug\dftables.pdb" /map:"$(INTDIR)\dftables.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\dftables.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dftables.obj"

"$(OUTDIR)\dftables.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
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


!IF "$(CFG)" == "dftables - Win32 Release" || "$(CFG)" ==\
 "dftables - Win32 Debug"
SOURCE=.\dftables.c
DEP_CPP_DFTAB=\
	".\config.h"\
	".\internal.h"\
	".\maketables.c"\
	".\pcre.h"\
	

"$(INTDIR)\dftables.obj" : $(SOURCE) $(DEP_CPP_DFTAB) "$(INTDIR)" ".\config.h"\
 ".\pcre.h"


SOURCE=.\config.hw

!IF  "$(CFG)" == "dftables - Win32 Release"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

InputPath=.\config.hw

".\config.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\config.hw .\config.h >nul 
	echo Created pcre config.h from config.hw 
	

!ENDIF 

SOURCE=.\maketables.c
SOURCE=.\pcre.hw

!IF  "$(CFG)" == "dftables - Win32 Release"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ELSEIF  "$(CFG)" == "dftables - Win32 Debug"

InputPath=.\pcre.hw

".\pcre.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy .\pcre.hw .\pcre.h >nul 
	echo Created pcre.h from pcre.hw 
	

!ENDIF 


!ENDIF 

