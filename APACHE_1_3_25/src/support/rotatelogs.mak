# Microsoft Developer Studio Generated NMAKE File, Based on rotatelogs.dsp
!IF "$(CFG)" == ""
CFG=rotatelogs - Win32 Debug
!MESSAGE No configuration specified. Defaulting to rotatelogs - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "rotatelogs - Win32 Release" && "$(CFG)" !=\
 "rotatelogs - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "rotatelogs.mak" CFG="rotatelogs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "rotatelogs - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "rotatelogs - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "rotatelogs - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ELSE 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\rotatelogs.idb"
	-@erase "$(INTDIR)\rotatelogs.obj"
	-@erase "$(OUTDIR)\rotatelogs.exe"
	-@erase "$(OUTDIR)\rotatelogs.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /I "..\os\win32" /D "WIN32" /D\
 "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\rotatelogs"\
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

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rotatelogs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib wsock32.lib /nologo /subsystem:console\
 /incremental:no /pdb:"$(OUTDIR)\rotatelogs.pdb" /map:"$(INTDIR)\rotatelogs.map"\
 /machine:I386 /out:"$(OUTDIR)\rotatelogs.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\os.obj" \
	"$(INTDIR)\rotatelogs.obj"

"$(OUTDIR)\rotatelogs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "rotatelogs - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ELSE 

ALL : "$(OUTDIR)\rotatelogs.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\os.obj"
	-@erase "$(INTDIR)\rotatelogs.idb"
	-@erase "$(INTDIR)\rotatelogs.obj"
	-@erase "$(OUTDIR)\rotatelogs.exe"
	-@erase "$(OUTDIR)\rotatelogs.map"
	-@erase "$(OUTDIR)\rotatelogs.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D\
 "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\rotatelogs" /FD /c 
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

RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\rotatelogs.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib wsock32.lib /nologo /subsystem:console\
 /incremental:no /pdb:"$(OUTDIR)\rotatelogs.pdb" /map:"$(INTDIR)\rotatelogs.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\rotatelogs.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\os.obj" \
	"$(INTDIR)\rotatelogs.obj"

"$(OUTDIR)\rotatelogs.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "rotatelogs - Win32 Release" || "$(CFG)" ==\
 "rotatelogs - Win32 Debug"
SOURCE=..\ap\ap_cpystrn.c
DEP_CPP_AP_CP=\
	"..\include\ap.h"\
	"..\include\ap_alloc.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	
NODEP_CPP_AP_CP=\
	"..\include\ap_config_auto.h"\
	"..\include\sfio.h"\
	

"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) $(DEP_CPP_AP_CP) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_snprintf.c
DEP_CPP_AP_SN=\
	"..\include\ap.h"\
	"..\include\ap_alloc.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	
NODEP_CPP_AP_SN=\
	"..\include\ap_config_auto.h"\
	"..\include\sfio.h"\
	

"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) $(DEP_CPP_AP_SN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\os\win32\os.c
DEP_CPP_OS_C4=\
	"..\os\win32\os.h"\
	

"$(INTDIR)\os.obj" : $(SOURCE) $(DEP_CPP_OS_C4) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\rotatelogs.c
DEP_CPP_ROTAT=\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_ROTAT=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\rotatelogs.obj" : $(SOURCE) $(DEP_CPP_ROTAT) "$(INTDIR)"



!ENDIF 

