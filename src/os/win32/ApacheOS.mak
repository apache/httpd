# Microsoft Developer Studio Generated NMAKE File, Based on ApacheOS.dsp
!IF "$(CFG)" == ""
CFG=ApacheOS - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ApacheOS - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheOS - Win32 Release" && "$(CFG)" !=\
 "ApacheOS - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheOS.mak" CFG="ApacheOS - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheOS - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheOS - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheOS - Win32 Release"

OUTDIR=.\ApacheOSR
INTDIR=.\ApacheOSR
# Begin Custom Macros
OutDir=.\ApacheOSR
ProjDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheOS.dll" "$(ProjDir)\..\..\main\os.h"

!ELSE 

ALL : "$(OUTDIR)\ApacheOS.dll" "$(ProjDir)\..\..\main\os.h"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheOS.dll"
	-@erase "$(OUTDIR)\ApacheOS.exp"
	-@erase "$(OUTDIR)\ApacheOS.lib"
	-@erase "$(ProjDir)\..\..\main\os.h"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\ApacheOS.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheOSR/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o NUL /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheOS.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheOS.pdb" /machine:I386 /out:"$(OUTDIR)\ApacheOS.dll"\
 /implib:"$(OUTDIR)\ApacheOS.lib" 
LINK32_OBJS= \
	"$(INTDIR)\os.obj"

"$(OUTDIR)\ApacheOS.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

ProjDir=.
InputPath=.\ApacheOSR\ApacheOS.dll
SOURCE=$(InputPath)

"$(ProjDir)\..\..\main\os.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	COPY os.h $(ProjDir)\..\..\main

!ELSEIF  "$(CFG)" == "ApacheOS - Win32 Debug"

OUTDIR=.\ApacheOSD
INTDIR=.\ApacheOSD
# Begin Custom Macros
OutDir=.\ApacheOSD
ProjDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheOS.dll" "$(ProjDir)\..\..\main\os.h"

!ELSE 

ALL : "$(OUTDIR)\ApacheOS.dll" "$(ProjDir)\..\..\main\os.h"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheOS.dll"
	-@erase "$(OUTDIR)\ApacheOS.exp"
	-@erase "$(OUTDIR)\ApacheOS.ilk"
	-@erase "$(OUTDIR)\ApacheOS.lib"
	-@erase "$(OUTDIR)\ApacheOS.pdb"
	-@erase "$(ProjDir)\..\..\main\os.h"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\ApacheOS.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheOSD/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o NUL /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheOS.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)\ApacheOS.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheOS.dll" /implib:"$(OUTDIR)\ApacheOS.lib" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\os.obj"

"$(OUTDIR)\ApacheOS.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

ProjDir=.
InputPath=.\ApacheOSD\ApacheOS.dll
SOURCE=$(InputPath)

"$(ProjDir)\..\..\main\os.h"	 : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	COPY os.h $(ProjDir)\..\..\main

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


!IF "$(CFG)" == "ApacheOS - Win32 Release" || "$(CFG)" ==\
 "ApacheOS - Win32 Debug"
SOURCE=.\os.c
DEP_CPP_OS_C0=\
	".\os.h"\
	

"$(INTDIR)\os.obj" : $(SOURCE) $(DEP_CPP_OS_C0) "$(INTDIR)"



!ENDIF 

