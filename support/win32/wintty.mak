# Microsoft Developer Studio Generated NMAKE File, Based on wintty.dsp
!IF "$(CFG)" == ""
CFG=wintty - Win32 Debug
!MESSAGE No configuration specified. Defaulting to wintty - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "wintty - Win32 Release" && "$(CFG)" != "wintty - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "wintty.mak" CFG="wintty - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "wintty - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "wintty - Win32 Debug" (based on "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "wintty - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\wintty.exe"

!ELSE 

ALL : "$(OUTDIR)\wintty.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\wintty.idb"
	-@erase "$(INTDIR)\wintty.obj"
	-@erase "$(OUTDIR)\wintty.exe"
	-@erase "$(OUTDIR)\wintty.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D\
 "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\wintty" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\wintty.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib /nologo /subsystem:console\
 /incremental:no /pdb:"$(OUTDIR)\wintty.pdb" /map:"$(INTDIR)\wintty.map"\
 /machine:I386 /out:"$(OUTDIR)\wintty.exe" 
LINK32_OBJS= \
	"$(INTDIR)\wintty.obj"

"$(OUTDIR)\wintty.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "wintty - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\wintty.exe"

!ELSE 

ALL : "$(OUTDIR)\wintty.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\wintty.idb"
	-@erase "$(INTDIR)\wintty.obj"
	-@erase "$(OUTDIR)\wintty.exe"
	-@erase "$(OUTDIR)\wintty.map"
	-@erase "$(OUTDIR)\wintty.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D\
 "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\wintty" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\wintty.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib /nologo /subsystem:console\
 /incremental:no /pdb:"$(OUTDIR)\wintty.pdb" /map:"$(INTDIR)\wintty.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\wintty.exe" 
LINK32_OBJS= \
	"$(INTDIR)\wintty.obj"

"$(OUTDIR)\wintty.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "wintty - Win32 Release" || "$(CFG)" == "wintty - Win32 Debug"
SOURCE=.\wintty.c

"$(INTDIR)\wintty.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

