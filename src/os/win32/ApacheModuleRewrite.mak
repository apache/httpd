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

!IF  "$(CFG)" == "ApacheModuleRewrite - Win32 Release"

OUTDIR=.\ApacheModuleRewriteR
INTDIR=.\ApacheModuleRewriteR
# Begin Custom Macros
OutDir=.\ApacheModuleRewriteR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\ApacheModuleRewrite.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_rewrite.obj"
	-@erase "$(INTDIR)\passwd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.dll"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.exp"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.lib"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /I "..\..\os\win32" /D\
 "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "NO_DBM_REWRITEMAP" /D "SHARED_MODULE" /D\
 "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleRewriteR/
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

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleRewrite.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleRewrite.pdb"\
 /map:"$(INTDIR)\ApacheModuleRewrite.map" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleRewrite.dll"\
 /implib:"$(OUTDIR)\ApacheModuleRewrite.lib" /base:@"BaseAddr.ref",mod_rewrite 
LINK32_OBJS= \
	"$(INTDIR)\mod_rewrite.obj" \
	"$(INTDIR)\passwd.obj" \
	"..\..\CoreR\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleRewrite.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleRewrite - Win32 Debug"

OUTDIR=.\ApacheModuleRewriteD
INTDIR=.\ApacheModuleRewriteD
# Begin Custom Macros
OutDir=.\ApacheModuleRewriteD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleRewrite.dll"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\ApacheModuleRewrite.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_rewrite.obj"
	-@erase "$(INTDIR)\passwd.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.dll"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.exp"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.lib"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.map"
	-@erase "$(OUTDIR)\ApacheModuleRewrite.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /I\
 "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "NO_DBM_REWRITEMAP" /D\
 "SHARED_MODULE" /D "WIN32_LEAN_AND_MEAN" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD\
 /c 
CPP_OBJS=.\ApacheModuleRewriteD/
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

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleRewrite.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleRewrite.pdb"\
 /map:"$(INTDIR)\ApacheModuleRewrite.map" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleRewrite.dll"\
 /implib:"$(OUTDIR)\ApacheModuleRewrite.lib" /base:@"BaseAddr.ref",mod_rewrite 
LINK32_OBJS= \
	"$(INTDIR)\mod_rewrite.obj" \
	"$(INTDIR)\passwd.obj" \
	"..\..\CoreD\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleRewrite.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheModuleRewrite - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleRewrite - Win32 Debug"

!IF  "$(CFG)" == "ApacheModuleRewrite - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "ApacheModuleRewrite - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Debug" RECURSE=1 
   cd ".\os\win32"

!ENDIF 

SOURCE=..\..\modules\standard\mod_rewrite.c
DEP_CPP_MOD_R=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_conf_globals.h"\
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
	
NODEP_CPP_MOD_R=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\ebcdic.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\mod_rewrite.obj" : $(SOURCE) $(DEP_CPP_MOD_R) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


SOURCE=.\passwd.c
DEP_CPP_PASSW=\
	".\passwd.h"\
	

"$(INTDIR)\passwd.obj" : $(SOURCE) $(DEP_CPP_PASSW) "$(INTDIR)"



!ENDIF 

