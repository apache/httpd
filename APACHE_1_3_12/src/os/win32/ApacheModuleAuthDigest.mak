# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleAuthDigest.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleAuthDigest - Win32 Debug
!MESSAGE No configuration specified. Defaulting to ApacheModuleAuthDigest -\
 Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleAuthDigest - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleAuthDigest - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleAuthDigest.mak"\
 CFG="ApacheModuleAuthDigest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleAuthDigest - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleAuthDigest - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheModuleAuthDigest - Win32 Release"

OUTDIR=.\ApacheModuleAuthDigestD
INTDIR=.\ApacheModuleAuthDigestD
# Begin Custom Macros
OutDir=.\.\ApacheModuleAuthDigestD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleAuthDigest.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleAuthDigest.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.dll"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.exp"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "SHARED_MODULE" /Fp"$(INTDIR)\ApacheModuleAuthDigest.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleAuthDigestD/
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
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleAuthDigest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\ApacheModuleAuthDigest.pdb" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleAuthDigest.dll"\
 /implib:"$(OUTDIR)\ApacheModuleAuthDigest.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj"

"$(OUTDIR)\ApacheModuleAuthDigest.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleAuthDigest - Win32 Debug"

OUTDIR=.\ApacheModuleAuthDigestD
INTDIR=.\ApacheModuleAuthDigestD
# Begin Custom Macros
OutDir=.\.\ApacheModuleAuthDigestD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleAuthDigest.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleAuthDigest.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.dll"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.exp"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.ilk"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.lib"
	-@erase "$(OUTDIR)\ApacheModuleAuthDigest.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "SHARED_MODULE"\
 /Fp"$(INTDIR)\ApacheModuleAuthDigest.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\ApacheModuleAuthDigestD/
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
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleAuthDigest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)\ApacheModuleAuthDigest.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)\ApacheModuleAuthDigest.dll"\
 /implib:"$(OUTDIR)\ApacheModuleAuthDigest.lib" /pdbtype:sept 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj"

"$(OUTDIR)\ApacheModuleAuthDigest.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheModuleAuthDigest - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleAuthDigest - Win32 Debug"
SOURCE=..\..\modules\experimental\mod_auth_digest.c
DEP_CPP_MOD_A=\
	"..\..\include\alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_md5.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\ap_sha1.h"\
	"..\..\include\buff.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_conf_globals.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\http_log.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\http_request.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_md5.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_auth_digest.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

