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

CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Apache - Win32 Release"

OUTDIR=.\ApacheR
INTDIR=.\ApacheR
# Begin Custom Macros
OutDir=.\.\ApacheR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "$(OUTDIR)\Apache.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\main_win32.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\Apache.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)\Apache.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheR/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:console\
 /incremental:no /pdb:"$(OUTDIR)\Apache.pdb" /machine:I386\
 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\main_win32.obj"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

OUTDIR=.\ApacheD
INTDIR=.\ApacheD
# Begin Custom Macros
OutDir=.\.\ApacheD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "$(OUTDIR)\Apache.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\main_win32.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\Apache.exe"
	-@erase "$(OUTDIR)\Apache.ilk"
	-@erase "$(OUTDIR)\Apache.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)\Apache.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheD/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:console\
 /incremental:yes /pdb:"$(OUTDIR)\Apache.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\main_win32.obj"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "Apache - Win32 Release" || "$(CFG)" == "Apache - Win32 Debug"
SOURCE=.\os\win32\main_win32.c

"$(INTDIR)\main_win32.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

