# Microsoft Developer Studio Generated NMAKE File, Based on htpasswd.dsp
!IF "$(CFG)" == ""
CFG=htpasswd - Win32 Debug
!MESSAGE No configuration specified. Defaulting to htpasswd - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "htpasswd - Win32 Release" && "$(CFG)" != "htpasswd - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "htpasswd.mak" CFG="htpasswd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "htpasswd - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "htpasswd - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "htpasswd - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

ALL : "$(OUTDIR)\htpasswd.exe"


CLEAN :
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\htpasswd_src.idb"
	-@erase "$(INTDIR)\htpasswd_src.pdb"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /I "..\include" /I "..\os\win32" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\htpasswd_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=ws2_32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\htpasswd.pdb" /debug /machine:I386 /out:"$(OUTDIR)\htpasswd.exe" /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\ap_base64.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\htpasswd.obj"

"$(OUTDIR)\htpasswd.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

ALL : "$(OUTDIR)\htpasswd.exe"


CLEAN :
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\htpasswd_src.idb"
	-@erase "$(INTDIR)\htpasswd_src.pdb"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\htpasswd_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=ws2_32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\htpasswd.pdb" /debug /machine:I386 /out:"$(OUTDIR)\htpasswd.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_base64.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\htpasswd.obj"

"$(OUTDIR)\htpasswd.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("htpasswd.dep")
!INCLUDE "htpasswd.dep"
!ELSE 
!MESSAGE Warning: cannot find "htpasswd.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "htpasswd - Win32 Release" || "$(CFG)" == "htpasswd - Win32 Debug"
SOURCE=..\ap\ap_base64.c

"$(INTDIR)\ap_base64.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_checkpass.c

"$(INTDIR)\ap_checkpass.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_cpystrn.c

"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_getpass.c

"$(INTDIR)\ap_getpass.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_md5c.c

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_sha1.c

"$(INTDIR)\ap_sha1.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_snprintf.c

"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\htpasswd.c

"$(INTDIR)\htpasswd.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

