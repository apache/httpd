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
!MESSAGE "ApacheOS - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "ApacheOS - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe

!IF  "$(CFG)" == "ApacheOS - Win32 Release"

OUTDIR=.\ApacheOSR
INTDIR=.\ApacheOSR
# Begin Custom Macros
OutDir=.\ApacheOSR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheOS.lib"

!ELSE 

ALL : "$(OUTDIR)\ApacheOS.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheOS.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\ApacheOS.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheOSR/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheOS.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\ApacheOS.lib" 
LIB32_OBJS= \
	"$(INTDIR)\os.obj"

"$(OUTDIR)\ApacheOS.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheOS - Win32 Debug"

OUTDIR=.\ApacheOSD
INTDIR=.\ApacheOSD
# Begin Custom Macros
OutDir=.\ApacheOSD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheOS.lib"

!ELSE 

ALL : "$(OUTDIR)\ApacheOS.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheOS.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\ApacheOS.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheOSD/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheOS.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\ApacheOS.lib" 
LIB32_OBJS= \
	"$(INTDIR)\os.obj"

"$(OUTDIR)\ApacheOS.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
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


!IF "$(CFG)" == "ApacheOS - Win32 Release" || "$(CFG)" ==\
 "ApacheOS - Win32 Debug"
SOURCE=.\os.c
DEP_CPP_OS_C0=\
	".\os.h"\
	

"$(INTDIR)\os.obj" : $(SOURCE) $(DEP_CPP_OS_C0) "$(INTDIR)"



!ENDIF 

