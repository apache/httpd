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

CPP=cl.exe
RSC=rc.exe

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
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\htpasswd.exe"

"$(OUTDIR)" :
	if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /ML /W3 /GX /O2 /I "..\include" /D "NDEBUG" /D "WIN32" /D\
 "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN" /Fp"$(INTDIR)\htpasswd.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \

LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ws2_32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /machine:I386 /out:"$(OUTDIR)\htpasswd.exe" 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_base64.obj" \
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
	-@erase "$(INTDIR)\ap_cpystrn.obj"
	-@erase "$(INTDIR)\ap_getpass.obj"
	-@erase "$(INTDIR)\ap_md5c.obj"
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\ap_sha1.obj"
	-@erase "$(INTDIR)\ap_checkpass.obj"
	-@erase "$(INTDIR)\ap_base64.obj"
	-@erase "$(INTDIR)\htpasswd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\htpasswd.exe"
	-@erase "$(OUTDIR)\htpasswd.ilk"
	-@erase "$(OUTDIR)\htpasswd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MLd /W3 /Gm /GX /Zi /Od /I "..\include" /D "_DEBUG" /D\
 "WIN32" /D "_CONSOLE" /D "_MBCS" /D "WIN32_LEAN_AND_MEAN"\
 /Fp"$(INTDIR)\htpasswd.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\htpasswd.bsc" 
BSC32_SBRS= \

LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib ws2_32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)\htpasswd.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\htpasswd.exe" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\ap_cpystrn.obj" \
	"$(INTDIR)\ap_getpass.obj" \
	"$(INTDIR)\ap_md5c.obj" \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\ap_sha1.obj" \
	"$(INTDIR)\ap_checkpass.obj" \
	"$(INTDIR)\ap_base64.obj" \
	"$(INTDIR)\htpasswd.obj"

"$(OUTDIR)\htpasswd.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

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


!IF "$(CFG)" == "htpasswd - Win32 Release" || "$(CFG)" ==\
 "htpasswd - Win32 Debug"
SOURCE=..\ap\ap_cpystrn.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_CP=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_CP=\
	"..\include\ap_config_auto.h"\
	"..\include\ebcdic.h"\
	"..\include\os.h"\
	"..\include\sfio.h"\


"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) $(DEP_CPP_AP_CP) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_CP=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\


"$(INTDIR)\ap_cpystrn.obj" : $(SOURCE) $(DEP_CPP_AP_CP) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\ap\ap_getpass.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_GE=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_GE=\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\


"$(INTDIR)\ap_getpass.obj" : $(SOURCE) $(DEP_CPP_AP_GE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_GE=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\


"$(INTDIR)\ap_getpass.obj" : $(SOURCE) $(DEP_CPP_AP_GE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

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

SOURCE=..\ap\ap_snprintf.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_SN=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_SN=\
	"..\include\ap_config_auto.h"\
	"..\include\ebcdic.h"\
	"..\include\os.h"\
	"..\include\sfio.h"\


"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) $(DEP_CPP_AP_SN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_SN=\
	"..\include\alloc.h"\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\buff.h"\
	"..\include\hsregex.h"\
	"..\include\httpd.h"\
	"..\include\util_uri.h"\
	"..\os\win32\os.h"\
	"..\os\win32\readdir.h"\


"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) $(DEP_CPP_AP_SN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\ap\ap_sha1.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_SH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_sha1.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_SH=\
	"..\ap\ebcdic.h"\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\


"$(INTDIR)\ap_sha1.obj" : $(SOURCE) $(DEP_CPP_AP_SH) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_SH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_sha1.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\


"$(INTDIR)\ap_sha1.obj" : $(SOURCE) $(DEP_CPP_AP_SH) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\ap\ap_checkpass.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_CH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_CH=\
	"..\ap\ebcdic.h"\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\


"$(INTDIR)\ap_checkpass.obj" : $(SOURCE) $(DEP_CPP_AP_CH) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_CH=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\


"$(INTDIR)\ap_checkpass.obj" : $(SOURCE) $(DEP_CPP_AP_CH) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=..\ap\ap_base64.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_AP_BA=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\

NODEP_CPP_AP_BA=\
	"..\ap\ebcdic.h"\
	"..\include\ap_config_auto.h"\
	"..\include\os.h"\


"$(INTDIR)\ap_base64.obj" : $(SOURCE) $(DEP_CPP_AP_BA) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "htpasswd - Win32 Debug"

DEP_CPP_AP_BA=\
	"..\include\ap.h"\
	"..\include\ap_config.h"\
	"..\include\ap_ctype.h"\
	"..\include\ap_mmn.h"\
	"..\include\hsregex.h"\
	"..\os\win32\os.h"\


"$(INTDIR)\ap_base64.obj" : $(SOURCE) $(DEP_CPP_AP_BA) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\htpasswd.c

!IF  "$(CFG)" == "htpasswd - Win32 Release"

DEP_CPP_HTPAS=\
	"..\include\ap.h"\
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
	"..\include\ap.h"\
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

