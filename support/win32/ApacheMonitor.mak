# Microsoft Developer Studio Generated NMAKE File, Based on ApacheMonitor.dsp
!IF "$(CFG)" == ""
CFG=ApacheMonitor - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ApacheMonitor - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheMonitor - Win32 Release" && "$(CFG)" != "ApacheMonitor - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheMonitor.mak" CFG="ApacheMonitor - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheMonitor - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "ApacheMonitor - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\ApacheMonitor.exe"


CLEAN :
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x41a /fo"$(INTDIR)\ApacheMonitor.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib version.lib comctl32.lib /nologo /subsystem:windows /incremental:no /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /machine:I386 /out:"$(OUTDIR)\ApacheMonitor.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ApacheMonitor.obj" \
	"$(INTDIR)\ApacheMonitor.res"

"$(OUTDIR)\ApacheMonitor.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheMonitor - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\ApacheMonitor.exe"


CLEAN :
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(INTDIR)\vc60.idb"
	-@erase "$(INTDIR)\vc60.pdb"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"
	-@erase "$(OUTDIR)\ApacheMonitor.ilk"
	-@erase "$(OUTDIR)\ApacheMonitor.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "STRICT" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /GZ /c 

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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
RSC_PROJ=/l 0x41a /fo"$(INTDIR)\ApacheMonitor.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib version.lib comctl32.lib /nologo /subsystem:windows /incremental:yes /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /debug /machine:I386 /out:"$(OUTDIR)\ApacheMonitor.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\ApacheMonitor.obj" \
	"$(INTDIR)\ApacheMonitor.res"

"$(OUTDIR)\ApacheMonitor.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("ApacheMonitor.dep")
!INCLUDE "ApacheMonitor.dep"
!ELSE 
!MESSAGE Warning: cannot find "ApacheMonitor.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "ApacheMonitor - Win32 Release" || "$(CFG)" == "ApacheMonitor - Win32 Debug"
SOURCE=.\ApacheMonitor.rc

"$(INTDIR)\ApacheMonitor.res" : $(SOURCE) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE)


SOURCE=.\ApacheMonitor.c

"$(INTDIR)\ApacheMonitor.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

