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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ap.lib"

!ELSE 

ALL : "$(OUTDIR)\ap.lib"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap.idb"
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

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /I "..\os\win32" /D "WIN32" /D\
 "NDEBUG" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ap" /FD /c 
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

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ap.lib"

!ELSE 

ALL : "$(OUTDIR)\ap.lib"

!ENDIF 

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

RSC=rc.exe
CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I "..\os\win32" /D\
 "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\ap" /FD /c 
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


!IF "$(CFG)" == "ap - Win32 Release" || "$(CFG)" == "ap - Win32 Debug"
SOURCE=.\ap_base64.c
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


SOURCE=.\ap_checkpass.c
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


SOURCE=.\ap_cpystrn.c
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


SOURCE=.\ap_fnmatch.c
DEP_CPP_AP_FN=\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\fnmatch.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	
NODEP_CPP_AP_FN=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\ap_fnmatch.obj" : $(SOURCE) $(DEP_CPP_AP_FN) "$(INTDIR)"


SOURCE=.\ap_md5c.c
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


SOURCE=.\ap_sha1.c
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


SOURCE=.\ap_signal.c
DEP_CPP_AP_SI=\
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
	
NODEP_CPP_AP_SI=\
	"..\include\ap_config_auto.h"\
	"..\include\sfio.h"\
	

"$(INTDIR)\ap_signal.obj" : $(SOURCE) $(DEP_CPP_AP_SI) "$(INTDIR)"


SOURCE=.\ap_slack.c
DEP_CPP_AP_SL=\
	"..\include\ap.h"\
	"..\include\ap_alloc.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_ebcdic.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\http_log.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	
NODEP_CPP_AP_SL=\
	"..\include\ap_config_auto.h"\
	"..\include\sfio.h"\
	

"$(INTDIR)\ap_slack.obj" : $(SOURCE) $(DEP_CPP_AP_SL) "$(INTDIR)"


SOURCE=.\ap_snprintf.c
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



!ENDIF 

