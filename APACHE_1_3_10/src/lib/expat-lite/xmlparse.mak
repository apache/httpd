# Microsoft Developer Studio Generated NMAKE File, Based on xmlparse.dsp
!IF "$(CFG)" == ""
CFG=xmlparse - Win32 Release
!MESSAGE No configuration specified. Defaulting to xmlparse - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "xmlparse - Win32 Release" && "$(CFG)" !=\
 "xmlparse - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xmlparse.mak" CFG="xmlparse - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xmlparse - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "xmlparse - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "xmlparse - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\xmlparse.dll"

!ELSE 

ALL : "xmltok - Win32 Release" "$(OUTDIR)\xmlparse.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"xmltok - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(OUTDIR)\xmlparse.dll"
	-@erase "$(OUTDIR)\xmlparse.exp"
	-@erase "$(OUTDIR)\xmlparse.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\xmltok" /I "..\xmlwf" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /D XMLTOKAPI=__declspec(dllimport) /D\
 XMLPARSEAPI=__declspec(dllexport) /Fp"$(INTDIR)\xmlparse.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\xmlparse.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /base:"0x20000000" /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\xmlparse.pdb" /machine:I386 /def:".\xmlparse.def"\
 /out:"$(OUTDIR)\xmlparse.dll" /implib:"$(OUTDIR)\xmlparse.lib" 
DEF_FILE= \
	".\xmlparse.def"
LINK32_OBJS= \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(OUTDIR)\xmltok.lib"

"$(OUTDIR)\xmlparse.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "xmlparse - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\xmlparse.dll"

!ELSE 

ALL : "xmltok - Win32 Debug" "$(OUTDIR)\xmlparse.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"xmltok - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\hashtable.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\xmlparse.obj"
	-@erase "$(OUTDIR)\xmlparse.dll"
	-@erase "$(OUTDIR)\xmlparse.exp"
	-@erase "$(OUTDIR)\xmlparse.ilk"
	-@erase "$(OUTDIR)\xmlparse.lib"
	-@erase "$(OUTDIR)\xmlparse.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Od /I "..\xmltok" /I "..\xmlwf" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D XMLTOKAPI=__declspec(dllimport) /D\
 XMLPARSEAPI=__declspec(dllexport) /Fp"$(INTDIR)\xmlparse.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /Zi /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\xmlparse.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /base:"0x20000000" /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)\xmlparse.pdb" /debug /machine:I386\
 /def:".\xmlparse.def" /out:"$(OUTDIR)\xmlparse.dll"\
 /implib:"$(OUTDIR)\xmlparse.lib" 
DEF_FILE= \
	".\xmlparse.def"
LINK32_OBJS= \
	"$(INTDIR)\hashtable.obj" \
	"$(INTDIR)\xmlparse.obj" \
	"$(OUTDIR)\xmltok.lib"

"$(OUTDIR)\xmlparse.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "xmlparse - Win32 Release" || "$(CFG)" ==\
 "xmlparse - Win32 Debug"
SOURCE=.\hashtable.c
DEP_CPP_HASHT=\
	".\hashtable.h"\
	".\xmldef.h"\
	
NODEP_CPP_HASHT=\
	".\ap_config.h"\
	".\nspr.h"\
	

"$(INTDIR)\hashtable.obj" : $(SOURCE) $(DEP_CPP_HASHT) "$(INTDIR)"


SOURCE=.\xmlparse.c
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


!IF  "$(CFG)" == "xmlparse - Win32 Release"

"xmltok - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\xmltok.mak" CFG="xmltok - Win32 Release" 
   cd "."

"xmltok - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\xmltok.mak" CFG="xmltok - Win32 Release"\
 RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "xmlparse - Win32 Debug"

"xmltok - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\xmltok.mak" CFG="xmltok - Win32 Debug" 
   cd "."

"xmltok - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\xmltok.mak" CFG="xmltok - Win32 Debug"\
 RECURSE=1 
   cd "."

!ENDIF 


!ENDIF 

