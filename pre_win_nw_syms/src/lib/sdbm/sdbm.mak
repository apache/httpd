# Microsoft Developer Studio Generated NMAKE File, Based on sdbm.dsp
!IF "$(CFG)" == ""
CFG=sdbm - Win32 Debug
!MESSAGE No configuration specified. Defaulting to sdbm - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "sdbm - Win32 Release" && "$(CFG)" != "sdbm - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sdbm.mak" CFG="sdbm - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sdbm - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "sdbm - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "sdbm - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\sdbm.lib"

!ELSE 

ALL : "$(OUTDIR)\sdbm.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\sdbm.idb"
	-@erase "$(INTDIR)\sdbm.obj"
	-@erase "$(INTDIR)\sdbm_hash.obj"
	-@erase "$(INTDIR)\sdbm_lock.obj"
	-@erase "$(INTDIR)\sdbm_pair.obj"
	-@erase "$(OUTDIR)\sdbm.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\..\include" /I "..\..\os\win32" /D "WIN32"\
 /D "NDEBUG" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\sdbm" /FD /c 
CPP_OBJS=.\LibR/
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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\sdbm.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\sdbm.lib" 
LIB32_OBJS= \
	"$(INTDIR)\sdbm.obj" \
	"$(INTDIR)\sdbm_hash.obj" \
	"$(INTDIR)\sdbm_lock.obj" \
	"$(INTDIR)\sdbm_pair.obj"

"$(OUTDIR)\sdbm.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "sdbm - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\sdbm.lib"

!ELSE 

ALL : "$(OUTDIR)\sdbm.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\sdbm.idb"
	-@erase "$(INTDIR)\sdbm.obj"
	-@erase "$(INTDIR)\sdbm.pdb"
	-@erase "$(INTDIR)\sdbm_hash.obj"
	-@erase "$(INTDIR)\sdbm_lock.obj"
	-@erase "$(INTDIR)\sdbm_pair.obj"
	-@erase "$(OUTDIR)\sdbm.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /D\
 "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\sdbm" /FD /c 
CPP_OBJS=.\LibD/
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

BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\sdbm.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\sdbm.lib" 
LIB32_OBJS= \
	"$(INTDIR)\sdbm.obj" \
	"$(INTDIR)\sdbm_hash.obj" \
	"$(INTDIR)\sdbm_lock.obj" \
	"$(INTDIR)\sdbm_pair.obj"

"$(OUTDIR)\sdbm.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "sdbm - Win32 Release" || "$(CFG)" == "sdbm - Win32 Debug"
SOURCE=.\sdbm.c
DEP_CPP_SDBM_=\
	".\sdbm.h"\
	".\sdbm_pair.h"\
	".\sdbm_tune.h"\
	

"$(INTDIR)\sdbm.obj" : $(SOURCE) $(DEP_CPP_SDBM_) "$(INTDIR)"


SOURCE=.\sdbm_hash.c
DEP_CPP_SDBM_H=\
	".\sdbm.h"\
	

"$(INTDIR)\sdbm_hash.obj" : $(SOURCE) $(DEP_CPP_SDBM_H) "$(INTDIR)"


SOURCE=.\sdbm_lock.c
DEP_CPP_SDBM_L=\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\hsregex.h"\
	"..\..\os\win32\os.h"\
	
NODEP_CPP_SDBM_L=\
	"..\..\include\ap_config_auto.h"\
	

"$(INTDIR)\sdbm_lock.obj" : $(SOURCE) $(DEP_CPP_SDBM_L) "$(INTDIR)"


SOURCE=.\sdbm_pair.c
DEP_CPP_SDBM_P=\
	".\sdbm.h"\
	".\sdbm_pair.h"\
	".\sdbm_tune.h"\
	

"$(INTDIR)\sdbm_pair.obj" : $(SOURCE) $(DEP_CPP_SDBM_P) "$(INTDIR)"



!ENDIF 

