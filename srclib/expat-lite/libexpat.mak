# Microsoft Developer Studio Generated NMAKE File, Based on libexpat.dsp
!IF "$(CFG)" == ""
CFG=libexpat - Win32 Debug
!MESSAGE No configuration specified. Defaulting to libexpat - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "libexpat - Win32 Release" && "$(CFG)" !=\
 "libexpat - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libexpat.mak" CFG="libexpat - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libexpat - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libexpat - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "libexpat - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\libexpat.dll"

!ELSE 

ALL : "$(OUTDIR)\libexpat.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\libexpat.idb"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(OUTDIR)\libexpat.dll"
	-@erase "$(OUTDIR)\libexpat.exp"
	-@erase "$(OUTDIR)\libexpat.lib"
	-@erase "$(OUTDIR)\libexpat.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D\
 "XML_MIN_SIZE" /D XMLTOKAPI="__declspec(dllexport)" /D\
 XMLPARSEAPI="__declspec(dllexport)" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\libexpat"\
 /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libexpat.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /base:"0x6EC00000" /dll /incremental:no\
 /pdb:"$(OUTDIR)\libexpat.pdb" /map:"$(INTDIR)\libexpat.map" /machine:I386\
 /out:"$(OUTDIR)\libexpat.dll" /implib:"$(OUTDIR)\libexpat.lib" 
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\libexpat.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "libexpat - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\libexpat.dll"

!ELSE 

ALL : "$(OUTDIR)\libexpat.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\libexpat.idb"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(OUTDIR)\libexpat.dll"
	-@erase "$(OUTDIR)\libexpat.exp"
	-@erase "$(OUTDIR)\libexpat.lib"
	-@erase "$(OUTDIR)\libexpat.map"
	-@erase "$(OUTDIR)\libexpat.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /D "_MBCS" /D "XML_MIN_SIZE" /D XMLTOKAPI="__declspec(dllexport)" /D\
 XMLPARSEAPI="__declspec(dllexport)" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\libexpat"\
 /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libexpat.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /base:"0x6EC00000" /dll /incremental:no\
 /pdb:"$(OUTDIR)\libexpat.pdb" /map:"$(INTDIR)\libexpat.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\libexpat.dll" /implib:"$(OUTDIR)\libexpat.lib" 
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\libexpat.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "libexpat - Win32 Release" || "$(CFG)" ==\
 "libexpat - Win32 Debug"
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

