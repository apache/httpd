# Microsoft Developer Studio Generated NMAKE File, Based on ap.dsp
!IF "$(CFG)" == ""
CFG=ap - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ap - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ap - Win32 Release" && "$(CFG)" != "ap - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ap.mak" CFG="ap - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ap - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "ap - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ap - Win32 Release"

OUTDIR=.\LibR
INTDIR=.\LibR
# Begin Custom Macros
OutDir=.\LibR
# End Custom Macros

ALL : "$(OUTDIR)\ap.lib"


CLEAN :
	-@erase "$(INTDIR)\ap.idb"
	-@erase "$(INTDIR)\ap.pdb"
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_fnmatch.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_signal.obj"
	-@erase "$(INTDIR)\ap_slack.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(OUTDIR)\ap.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /I "..\include" /I "..\os\win32" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ap" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ap.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\ap.lib" 
LIB32_OBJS= \
	"$(INTDIR)\ap_base64.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_fnmatch.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_signal.obj" \
	"$(INTDIR)\ap_slack.obj" \
	"$(INTDIR)\ap_snprintf.obj"

"$(OUTDIR)\ap.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ap - Win32 Debug"

OUTDIR=.\LibD
INTDIR=.\LibD
# Begin Custom Macros
OutDir=.\LibD
# End Custom Macros

ALL : "$(OUTDIR)\ap.lib"


CLEAN :
	-@erase "$(INTDIR)\ap.idb"
	-@erase "$(INTDIR)\ap.pdb"
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_fnmatch.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_signal.obj"
	-@erase "$(INTDIR)\ap_slack.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(OUTDIR)\ap.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ap" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ap.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
LIB32_FLAGS=/nologo /out:"$(OUTDIR)\ap.lib" 
LIB32_OBJS= \
	"$(INTDIR)\ap_base64.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_fnmatch.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_signal.obj" \
	"$(INTDIR)\ap_slack.obj" \
	"$(INTDIR)\ap_snprintf.obj"

"$(OUTDIR)\ap.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("ap.dep")
!INCLUDE "ap.dep"
!ELSE 
!MESSAGE Warning: cannot find "ap.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "ap - Win32 Release" || "$(CFG)" == "ap - Win32 Debug"
SOURCE=.\ap_base64.c

"$(INTDIR)\ap_base64.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_checkpass.c

"$(INTDIR)\ap_checkpass.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_cpystrn.c

"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_fnmatch.c

"$(INTDIR)\ap_fnmatch.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_md5c.c

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_sha1.c

"$(INTDIR)\ap_sha1.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_signal.c

"$(INTDIR)\ap_signal.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_slack.c

"$(INTDIR)\ap_slack.obj" : $(SOURCE) "$(INTDIR)"


SOURCE=.\ap_snprintf.c

"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) "$(INTDIR)"



!ENDIF 

