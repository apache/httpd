# Microsoft Developer Studio Generated NMAKE File, Based on Win9xConHook.dsp
!IF "$(CFG)" == ""
CFG=Win9xConHook - Win32 Release
!MESSAGE No configuration specified. Defaulting to Win9xConHook - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "Win9xConHook - Win32 Release" && "$(CFG)" !=\
 "Win9xConHook - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Win9xConHook.mak" CFG="Win9xConHook - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Win9xConHook - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "Win9xConHook - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "Win9xConHook - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Win9xConHook.dll"

!ELSE 

ALL : "$(OUTDIR)\Win9xConHook.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\Win9xConHook.idb"
	-@erase "$(INTDIR)\Win9xConHook.obj"
	-@erase "$(OUTDIR)\Win9xConHook.dll"
	-@erase "$(OUTDIR)\Win9xConHook.exp"
	-@erase "$(OUTDIR)\Win9xConHook.lib"
	-@erase "$(OUTDIR)\Win9xConHook.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Win9xConHook" /FD /c 
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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Win9xConHook.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib /nologo /base:"0x1c0f0000"\
 /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\Win9xConHook.pdb"\
 /map:"$(INTDIR)\Win9xConHook.map" /machine:I386 /def:".\Win9xConHook.def"\
 /out:"$(OUTDIR)\Win9xConHook.dll" /implib:"$(OUTDIR)\Win9xConHook.lib" 
DEF_FILE= \
	".\Win9xConHook.def"
LINK32_OBJS= \
	"$(INTDIR)\Win9xConHook.obj"

"$(OUTDIR)\Win9xConHook.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Win9xConHook - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Win9xConHook.dll"

!ELSE 

ALL : "$(OUTDIR)\Win9xConHook.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\Win9xConHook.idb"
	-@erase "$(INTDIR)\Win9xConHook.obj"
	-@erase "$(OUTDIR)\Win9xConHook.dll"
	-@erase "$(OUTDIR)\Win9xConHook.exp"
	-@erase "$(OUTDIR)\Win9xConHook.lib"
	-@erase "$(OUTDIR)\Win9xConHook.map"
	-@erase "$(OUTDIR)\Win9xConHook.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Win9xConHook" /FD /c 
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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Win9xConHook.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib /nologo /base:"0x1c0f0000"\
 /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\Win9xConHook.pdb"\
 /map:"$(INTDIR)\Win9xConHook.map" /debug /machine:I386\
 /def:".\Win9xConHook.def" /out:"$(OUTDIR)\Win9xConHook.dll"\
 /implib:"$(OUTDIR)\Win9xConHook.lib" 
DEF_FILE= \
	".\Win9xConHook.def"
LINK32_OBJS= \
	"$(INTDIR)\Win9xConHook.obj"

"$(OUTDIR)\Win9xConHook.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "Win9xConHook - Win32 Release" || "$(CFG)" ==\
 "Win9xConHook - Win32 Debug"
SOURCE=.\Win9xConHook.c

"$(INTDIR)\Win9xConHook.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

