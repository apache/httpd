# Microsoft Developer Studio Generated NMAKE File, Based on htpasswd.dsp
!IF "$(CFG)" == ""
CFG=htpasswd - Win32 Debug
!MESSAGE No configuration specified. Defaulting to htpasswd - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "htpasswd - Win32 Release" && "$(CFG)" !=\
 "htpasswd - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "htpasswd.mak" CFG="htpasswd - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "htpasswd - Win32 Release" (based on\
 "Win32 (x86) Console Application")
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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\htpasswd.exe"

!ELSE 

ALL : "$(OUTDIR)\htpasswd.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\htpasswd.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\include" /D "WIN32" /D "NDEBUG" /D\
 "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\htpasswd.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /machine:I386 /out:"$(OUTDIR)\htpasswd.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_md5c.obj" \
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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\htpasswd.exe"

!ELSE 

ALL : "$(OUTDIR)\htpasswd.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.ilk"
	-@erase "$(OUTDIR)\htpasswd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\include" /D "WIN32" /D\
 "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fp"$(INTDIR)\htpasswd.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib\
 odbccp32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\htpasswd.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\htpasswd.obj"

"$(OUTDIR)\htpasswd.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "htpasswd - Win32 Release" || "$(CFG)" ==\
 "htpasswd - Win32 Debug"
SOURCE=..\ap\ap_md5c.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_MD=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_AP_MD=\
	"..\ap\ebcdic.h"\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\
	

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) $(DEP_CPP_AP_MD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_MD=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) $(DEP_CPP_AP_MD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\htpasswd.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_HTPAS=\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\getopt.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_HTPAS=\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\
	

"$(INTDIR)\htpasswd.obj" : $(SOURCE) $(DEP_CPP_HTPAS) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_HTPAS=\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\getopt.h"\
	"..\os\win32\os.h"\
	

"$(INTDIR)\htpasswd.obj" : $(SOURCE) $(DEP_CPP_HTPAS) "$(INTDIR)"


!ENDIF 


!ENDIF 

