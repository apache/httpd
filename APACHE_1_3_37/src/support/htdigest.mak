# Microsoft Developer Studio Generated NMAKE File, Based on htdigest.dsp
!IF "$(CFG)" == ""
CFG=htdigest - Win32 Debug
!MESSAGE No configuration specified. Defaulting to htdigest - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "htdigest - Win32 Release" && "$(CFG)" != "htdigest - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "htdigest.mak" CFG="htdigest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "htdigest - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "htdigest - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "htdigest - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\htdigest.exe"


CLEAN :
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\htdigest.obj"
	-@erase "$(INTDIR)\htdigest_src.idb"
	-@erase "$(INTDIR)\htdigest_src.pdb"
	-@erase "$(OUTDIR)\htdigest.exe"
	-@erase "$(OUTDIR)\htdigest.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "..\include" /I "..\os\win32" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\htdigest_src" /FD /c 

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

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htdigest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\htdigest.pdb" /debug /machine:I386 /out:"$(OUTDIR)\htdigest.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\htdigest.obj"

"$(OUTDIR)\htdigest.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "htdigest - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\htdigest.exe"


CLEAN :
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\htdigest.obj"
	-@erase "$(INTDIR)\htdigest_src.idb"
	-@erase "$(INTDIR)\htdigest_src.pdb"
	-@erase "$(OUTDIR)\htdigest.exe"
	-@erase "$(OUTDIR)\htdigest.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\htdigest_src" /FD /c 

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

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htdigest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=/nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\htdigest.pdb" /debug /machine:I386 /out:"$(OUTDIR)\htdigest.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\htdigest.obj"

"$(OUTDIR)\htdigest.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("htdigest.dep")
!INCLUDE "htdigest.dep"
!ELSE 
!MESSAGE Warning: cannot find "htdigest.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "htdigest - Win32 Release" || "$(CFG)" == "htdigest - Win32 Debug"
SOURCE=..\ap\ap_cpystrn.c

"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_getpass.c

"$(INTDIR)\ap_getpass.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_md5c.c

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\htdigest.c

"$(INTDIR)\htdigest.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

