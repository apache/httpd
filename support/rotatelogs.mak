# Microsoft Developer Studio Generated NMAKE File, Based on rotatelogs.dsp
!IF "$(CFG)" == ""
CFG=rotatelogs - Win32 Debug
!MESSAGE No configuration specified. Defaulting to rotatelogs - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "rotatelogs - Win32 Release" && "$(CFG)" !=\
 "rotatelogs - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "rotatelogs.mak" CFG="rotatelogs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "rotatelogs - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "rotatelogs - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "rotatelogs - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ELSE 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\rotatelogs.idb"
	-@erase "$(INTDIR)\rotatelogs.obj"
	-@erase "$(OUTDIR)\rotatelogs.exe"
	-@erase "$(OUTDIR)\rotatelogs.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D\
 "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\rotatelogs" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rotatelogs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo\
 /subsystem:console /incremental:no /pdb:"$(OUTDIR)\rotatelogs.pdb"\
 /map:"$(INTDIR)\rotatelogs.map" /machine:I386 /out:"$(OUTDIR)\rotatelogs.exe" 
LINK32_OBJS= \
	"$(INTDIR)\rotatelogs.obj"

"$(OUTDIR)\rotatelogs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "rotatelogs - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ELSE 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\rotatelogs.idb"
	-@erase "$(INTDIR)\rotatelogs.obj"
	-@erase "$(OUTDIR)\rotatelogs.exe"
	-@erase "$(OUTDIR)\rotatelogs.map"
	-@erase "$(OUTDIR)\rotatelogs.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "../srclib/apr/include" /I\
 "../srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D\
 "APR_DECLARE_STATIC" /D "APU_DECLARE_STATIC" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\rotatelogs" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rotatelogs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib wsock32.lib ws2_32.lib /nologo\
 /subsystem:console /incremental:no /pdb:"$(OUTDIR)\rotatelogs.pdb"\
 /map:"$(INTDIR)\rotatelogs.map" /debug /machine:I386\
 /out:"$(OUTDIR)\rotatelogs.exe" 
LINK32_OBJS= \
	"$(INTDIR)\rotatelogs.obj"

"$(OUTDIR)\rotatelogs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "rotatelogs - Win32 Release" || "$(CFG)" ==\
 "rotatelogs - Win32 Debug"
SOURCE=.\rotatelogs.c
DEP_CPP_ROTAT=\
	"..\srclib\apr\include\apr.h"\
	

"$(INTDIR)\rotatelogs.obj" : $(SOURCE) $(DEP_CPP_ROTAT) "$(INTDIR)"



!ENDIF 

