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
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\htpasswd.idb"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /I "..\os\win32" /D "NDEBUG" /D\
 "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\htpasswd" /FD /c 
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
LINK32_FLAGS=ws2_32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /map:"$(INTDIR)\htpasswd.map" /machine:I386\
 /out:"$(OUTDIR)\htpasswd.exe" 
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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\htpasswd.exe"

!ELSE 

ALL : "$(OUTDIR)\htpasswd.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\htpasswd.idb"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.map"
	-@erase "$(OUTDIR)\htpasswd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D\
 "_DEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\htpasswd" /FD /c 
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
LINK32_FLAGS=ws2_32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /map:"$(INTDIR)\htpasswd.map" /debug\
 /machine:I386 /out:"$(OUTDIR)\htpasswd.exe" 
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


!IF "$(CFG)" == "htpasswd - Win32 Release" || "$(CFG)" ==\
 "htpasswd - Win32 Debug"
SOURCE=..\ap\ap_base64.c
DEP_CPP_AP_BA=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_BA=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_base64.obj" : $(SOURCE) $(DEP_CPP_AP_BA) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_checkpass.c
DEP_CPP_AP_CH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\ap_sha1.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_CH=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_checkpass.obj" : $(SOURCE) $(DEP_CPP_AP_CH) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


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


SOURCE=..\ap\ap_getpass.c
DEP_CPP_AP_GE=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_GE=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_getpass.obj" : $(SOURCE) $(DEP_CPP_AP_GE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_md5c.c
DEP_CPP_AP_MD=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_MD=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_md5c.obj" : $(SOURCE) $(DEP_CPP_AP_MD) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=..\ap\ap_sha1.c
DEP_CPP_AP_SH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_mmn.h"\
	"..\include\ap_sha1.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_SH=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_sha1.obj" : $(SOURCE) $(DEP_CPP_AP_SH) "$(INTDIR)"
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


SOURCE=.\htpasswd.c
DEP_CPP_HTPAS=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_md5.h"\
	"..\include\ap_mmn.h"\
	"..\include\ap_sha1.h"\
	"..\include\hsregex.h"\
	"..\os\win32\getopt.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_HTPAS=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\htpasswd.obj" : $(SOURCE) $(DEP_CPP_HTPAS) "$(INTDIR)"



!ENDIF 

