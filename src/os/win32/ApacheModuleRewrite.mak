# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleRewrite.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleRewrite - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleRewrite - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleRewrite - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleRewrite - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleRewrite.mak"\
 CFG="ApacheModuleRewrite - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleRewrite - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleRewrite - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheModuleRewrite - Win32 Release"

OUTDIR=.\ApacheModuleRewriteR
INTDIR=.\ApacheModuleRewriteR
# Begin Custom Macros
OutDir=.\.\ApacheModuleRewriteR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_rewrite.obj"
	-@erase "$(INTDIR)\passwd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.dll"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.exp"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "NO_DBM_REWRITEMAP" /D "SHARED_MODULE"\
 /Fp"$(INTDIR)\ApacheModuleRewrite.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\ApacheModuleRewriteR/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleRewrite.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib wsock32.lib /nologo\
 /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleRewrite.pdb" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleRewrite.dll"\
 /implib:"$(OUTDIR)\ApacheModuleRewrite.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_rewrite.obj" \
	"$(INTDIR)\passwd.obj"

"$(OUTDIR)\ApacheModuleRewrite.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleRewrite - Win32 Debug"

OUTDIR=.\ApacheModuleRewriteD
INTDIR=.\ApacheModuleRewriteD
# Begin Custom Macros
OutDir=.\.\ApacheModuleRewriteD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_rewrite.obj"
	-@erase "$(INTDIR)\passwd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.dll"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.exp"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.ilk"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.lib"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "NO_DBM_REWRITEMAP" /D "SHARED_MODULE"\
 /Fp"$(INTDIR)\ApacheModuleRewrite.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\ApacheModuleRewriteD/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleRewrite.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib wsock32.lib /nologo\
 /subsystem:windows /dll /incremental:yes\
 /pdb:"$(OUTDIR)\ApacheModuleRewrite.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleRewrite.dll"\
 /implib:"$(OUTDIR)\ApacheModuleRewrite.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_rewrite.obj" \
	"$(INTDIR)\passwd.obj"

"$(OUTDIR)\ApacheModuleRewrite.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "ApacheModuleRewrite - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleRewrite - Win32 Debug"
SOURCE=..\..\modules\standard\mod_rewrite.c

!IF  "$(CFG)" == "ApacheModuleRewrite - Win32 Release"

DEP_CPP_MOD_R=\
	"..\..\include\alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\conf.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\modules\standard\mod_rewrite.h"\
	".\os.h"\
	".\passwd.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_rewrite.obj" : $(SOURCE) $(DEP_CPP_MOD_R) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheModuleRewrite - Win32 Debug"

DEP_CPP_MOD_R=\
	"..\..\include\alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\conf.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_request.h"\
	"..\..\include\http_vhost.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	"..\..\modules\standard\mod_rewrite.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_rewrite.obj" : $(SOURCE) $(DEP_CPP_MOD_R) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\passwd.c
DEP_CPP_PASSW=\
	".\passwd.h"\
	

"$(INTDIR)\passwd.obj" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"



!ENDIF 

