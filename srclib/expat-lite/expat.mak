# Microsoft Developer Studio Generated NMAKE File, Based on expat.dsp
!IF "$(CFG)" == ""
CFG=expat - Win32 Debug
!MESSAGE No configuration specified. Defaulting to expat - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "expat - Win32 Release" && "$(CFG)" != "expat - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "expat.mak" CFG="expat - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "expat - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "expat - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "expat - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\expat.lib"

!ELSE 

ALL : "$(OUTDIR)\expat.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\expat.idb"
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(OUTDIR)\expat.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "XML_MIN_SIZE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\expat" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\expat.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\expat.lib" 
LIB32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\expat.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "expat - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\expat.lib"

!ELSE 

ALL : "$(OUTDIR)\expat.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\expat.idb"
	-@erase "$(INTDIR)\expat.pdb"
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(OUTDIR)\expat.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D\
 "XML_MIN_SIZE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\expat" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\expat.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\expat.lib" 
LIB32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\expat.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "expat - Win32 Release" || "$(CFG)" == "expat - Win32 Debug"
SOURCE=".\dllmain.c"

"$(INTDIR)\dllmain.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=".\hashtable.c"
DEP_CPP_HASHT=\
	".\hashtable.h"\
	".\xmldef.h"\
	
NODEP_CPP_HASHT=\
	".\ap_config.h"\
	".\nspr.h"\
	

"$(INTDIR)\hashtable.obj" : $(SOURCE) $(DEP_CPP_HASHT) "$(INTDIR)"


SOURCE=".\xmlparse.c"
DEP_CPP_XMLPA=\
	".\hashtable.h"\
	".\xmldef.h"\
	".\xmlparse.h"\
	".\xmlrole.h"\
	".\xmltok.h"\
	
NODEP_CPP_XMLPA=\
	".\ap_config.h"\
	".\nspr.h"\
	

"$(INTDIR)\xmlparse.obj" : $(SOURCE) $(DEP_CPP_XMLPA) "$(INTDIR)"


SOURCE=".\xmlrole.c"
DEP_CPP_XMLRO=\
	".\xmldef.h"\
	".\xmlrole.h"\
	".\xmltok.h"\
	
NODEP_CPP_XMLRO=\
	".\ap_config.h"\
	".\nspr.h"\
	

"$(INTDIR)\xmlrole.obj" : $(SOURCE) $(DEP_CPP_XMLRO) "$(INTDIR)"


SOURCE=".\xmltok.c"
DEP_CPP_XMLTO=\
	".\asciitab.h"\
	".\iasciitab.h"\
	".\latin1tab.h"\
	".\nametab.h"\
	".\utf8tab.h"\
	".\xmldef.h"\
	".\xmltok.h"\
	".\xmltok_impl.c"\
	".\xmltok_impl.h"\
	".\xmltok_ns.c"\
	
NODEP_CPP_XMLTO=\
	".\ap_config.h"\
	".\nspr.h"\
	

"$(INTDIR)\xmltok.obj" : $(SOURCE) $(DEP_CPP_XMLTO) "$(INTDIR)"



!ENDIF 

