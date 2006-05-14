# Microsoft Developer Studio Generated NMAKE File, Based on xmltok.dsp
!IF "$(CFG)" == ""
CFG=xmltok - Win32 Release
!MESSAGE No configuration specified. Defaulting to xmltok - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "xmltok - Win32 Release" && "$(CFG)" != "xmltok - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "xmltok.mak" CFG="xmltok - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "xmltok - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "xmltok - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "xmltok - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\xmltok.dll"


CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(INTDIR)\xmltok_src.idb"
	-@erase "$(INTDIR)\xmltok_src.pdb"
	-@erase "$(OUTDIR)\xmltok.dll"
	-@erase "$(OUTDIR)\xmltok.exp"
	-@erase "$(OUTDIR)\xmltok.lib"
	-@erase "$(OUTDIR)\xmltok.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D XMLTOKAPI=__declspec(dllexport) /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\xmltok_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\xmltok.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\xmltok.pdb" /debug /machine:I386 /def:".\xmltok.def" /out:"$(OUTDIR)\xmltok.dll" /implib:"$(OUTDIR)\xmltok.lib" /base:@"..\..\os\win32\BaseAddr.ref",xmltok /opt:ref 
DEF_FILE= \
	".\xmltok.def"
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\xmltok.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "xmltok - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\xmltok.dll"


CLEAN :
	-@erase "$(INTDIR)\dllmain.obj"
	-@erase "$(INTDIR)\xmlrole.obj"
	-@erase "$(INTDIR)\xmltok.obj"
	-@erase "$(INTDIR)\xmltok_src.idb"
	-@erase "$(INTDIR)\xmltok_src.pdb"
	-@erase "$(OUTDIR)\xmltok.dll"
	-@erase "$(OUTDIR)\xmltok.exp"
	-@erase "$(OUTDIR)\xmltok.lib"
	-@erase "$(OUTDIR)\xmltok.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D XMLTOKAPI=__declspec(dllexport) /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\xmltok_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\xmltok.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\xmltok.pdb" /debug /machine:I386 /def:".\xmltok.def" /out:"$(OUTDIR)\xmltok.dll" /implib:"$(OUTDIR)\xmltok.lib" /base:@"..\..\os\win32\BaseAddr.ref",xmltok 
DEF_FILE= \
	".\xmltok.def"
LINK32_OBJS= \
	"$(INTDIR)\dllmain.obj" \
	"$(INTDIR)\xmlrole.obj" \
	"$(INTDIR)\xmltok.obj"

"$(OUTDIR)\xmltok.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("xmltok.dep")
!INCLUDE "xmltok.dep"
!ELSE 
!MESSAGE Warning: cannot find "xmltok.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "xmltok - Win32 Release" || "$(CFG)" == "xmltok - Win32 Debug"
SOURCE=.\dllmain.c

"$(INTDIR)\dllmain.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\xmlrole.c

"$(INTDIR)\xmlrole.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\xmltok.c

"$(INTDIR)\xmltok.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\xmltok_impl.c

!ENDIF 

