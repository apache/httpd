# Microsoft Developer Studio Generated NMAKE File, Based on Apache.dsp
!IF "$(CFG)" == ""
CFG=Apache - Win32 Release
!MESSAGE No configuration specified. Defaulting to Apache - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "Apache - Win32 Release" && "$(CFG)" != "Apache - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak" CFG="Apache - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Apache - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "Apache - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "Apache - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\Apache.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\Apache.idb"
	-@erase "$(INTDIR)\apache.res"
	-@erase "$(INTDIR)\main_win32.obj"
	-@erase "$(OUTDIR)\Apache.exe"
	-@erase "$(OUTDIR)\Apache.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Apache" /FD /c 
CPP_OBJS=.\Release/
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

RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\apache.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Apache.pdb" /map:"$(INTDIR)\Apache.map" /machine:I386\
 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\apache.res" \
	"$(INTDIR)\main_win32.obj" \
	"$(OUTDIR)\ApacheCore.lib"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\Apache.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\Apache.idb"
	-@erase "$(INTDIR)\apache.res"
	-@erase "$(INTDIR)\main_win32.obj"
	-@erase "$(OUTDIR)\Apache.exe"
	-@erase "$(OUTDIR)\Apache.map"
	-@erase "$(OUTDIR)\Apache.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Apache" /FD /c 
CPP_OBJS=.\Debug/
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

RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\apache.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Apache.pdb" /map:"$(INTDIR)\Apache.map" /debug /machine:I386\
 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\apache.res" \
	"$(INTDIR)\main_win32.obj" \
	"$(OUTDIR)\ApacheCore.lib"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "Apache - Win32 Release" || "$(CFG)" == "Apache - Win32 Debug"
SOURCE=.\os\win32\apache.rc
DEP_RSC_APACH=\
	".\os\win32\apache.ico"\
	

!IF  "$(CFG)" == "Apache - Win32 Release"


"$(INTDIR)\apache.res" : $(SOURCE) $(DEP_RSC_APACH) "$(INTDIR)"
	$(RSC) /l 0x809 /fo"$(INTDIR)\apache.res" /i "os\win32" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"


"$(INTDIR)\apache.res" : $(SOURCE) $(DEP_RSC_APACH) "$(INTDIR)"
	$(RSC) /l 0x809 /fo"$(INTDIR)\apache.res" /i "os\win32" /d "_DEBUG" $(SOURCE)


!ENDIF 

!IF  "$(CFG)" == "Apache - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd "."

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd "."

"ApacheCore - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Debug" RECURSE=1 
   cd "."

!ENDIF 

SOURCE=.\os\win32\main_win32.c

"$(INTDIR)\main_win32.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

