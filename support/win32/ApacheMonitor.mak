# Microsoft Developer Studio Generated NMAKE File, Based on ApacheMonitor.dsp
!IF "$(CFG)" == ""
CFG=ApacheMonitor - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ApacheMonitor - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheMonitor - Win32 Release" && "$(CFG)" !=\
 "ApacheMonitor - Win32 Debug"
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

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheMonitor - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheMonitor.exe"

!ELSE 

ALL : "$(OUTDIR)\ApacheMonitor.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ApacheMonitor.idb"
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"
	-@erase "$(OUTDIR)\ApacheMonitor.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheMonitor" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o NUL /win32 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ApacheMonitor.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib advapi32.lib comctl32.lib\
 shell32.lib version.lib /nologo /subsystem:windows /incremental:no\
 /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /map:"$(INTDIR)\ApacheMonitor.map"\
 /machine:I386 /out:"$(OUTDIR)\ApacheMonitor.exe" 
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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheMonitor.exe"

!ELSE 

ALL : "$(OUTDIR)\ApacheMonitor.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ApacheMonitor.idb"
	-@erase "$(INTDIR)\ApacheMonitor.obj"
	-@erase "$(INTDIR)\ApacheMonitor.res"
	-@erase "$(OUTDIR)\ApacheMonitor.exe"
	-@erase "$(OUTDIR)\ApacheMonitor.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ApacheMonitor" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o NUL /win32 
RSC_PROJ=/l 0x409 /fo"$(INTDIR)\ApacheMonitor.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheMonitor.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib advapi32.lib comctl32.lib\
 shell32.lib version.lib /nologo /subsystem:windows /incremental:no\
 /pdb:"$(OUTDIR)\ApacheMonitor.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheMonitor.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ApacheMonitor.obj" \
	"$(INTDIR)\ApacheMonitor.res"

"$(OUTDIR)\ApacheMonitor.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "ApacheMonitor - Win32 Release" || "$(CFG)" ==\
 "ApacheMonitor - Win32 Debug"
SOURCE=.\ApacheMonitor.rc
DEP_RSC_APACH=\
	".\apache_header.bmp"\
	".\ApacheMonitor.ico"\
	".\aprun.ico"\
	".\apsmall.ico"\
	".\apsrvmon.ico"\
	".\apstop.ico"\
	".\srun.bmp"\
	".\sstop.bmp"\
	

"$(INTDIR)\ApacheMonitor.res" : $(SOURCE) $(DEP_RSC_APACH) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE)


SOURCE=.\ApacheMonitor.c

"$(INTDIR)\ApacheMonitor.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

