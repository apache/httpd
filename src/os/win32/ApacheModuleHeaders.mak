# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleHeaders.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleHeaders - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleHeaders - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleHeaders - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleHeaders - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleHeaders.mak"\
 CFG="ApacheModuleHeaders - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleHeaders - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleHeaders - Win32 Debug" (based on\
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

!IF  "$(CFG)" == "ApacheModuleHeaders - Win32 Release"

OUTDIR=.\ApacheModuleHeadersR
INTDIR=.\ApacheModuleHeadersR
# Begin Custom Macros
OutDir=.\ApacheModuleHeadersR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\ApacheModuleHeaders.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_headers.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.dll"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.exp"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.lib"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleHeadersR/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleHeaders.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\ApacheModuleHeaders.pdb"\
 /map:"$(INTDIR)\ApacheModuleHeaders.map" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleHeaders.dll"\
 /implib:"$(OUTDIR)\ApacheModuleHeaders.lib" /base:@"BaseAddr.ref",mod_headers 
LINK32_OBJS= \
	"$(INTDIR)\mod_headers.obj" \
	"..\..\CoreR\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleHeaders.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleHeaders - Win32 Debug"

OUTDIR=.\ApacheModuleHeadersD
INTDIR=.\ApacheModuleHeadersD
# Begin Custom Macros
OutDir=.\ApacheModuleHeadersD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\ApacheModuleHeaders.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_headers.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.dll"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.exp"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.lib"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.map"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD\
 /c 
CPP_OBJS=.\ApacheModuleHeadersD/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleHeaders.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\ApacheModuleHeaders.pdb"\
 /map:"$(INTDIR)\ApacheModuleHeaders.map" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleHeaders.dll"\
 /implib:"$(OUTDIR)\ApacheModuleHeaders.lib" /base:@"BaseAddr.ref",mod_headers 
LINK32_OBJS= \
	"$(INTDIR)\mod_headers.obj" \
	"..\..\CoreD\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleHeaders.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "ApacheModuleHeaders - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleHeaders - Win32 Debug"
SOURCE=..\..\modules\standard\mod_headers.c

!IF  "$(CFG)" == "ApacheModuleHeaders - Win32 Release"

DEP_CPP_MOD_H=\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_headers.obj" : $(SOURCE) $(DEP_CPP_MOD_H) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheModuleHeaders - Win32 Debug"

DEP_CPP_MOD_H=\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_headers.obj" : $(SOURCE) $(DEP_CPP_MOD_H) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

!IF  "$(CFG)" == "ApacheModuleHeaders - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "\live\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "\live\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "ApacheModuleHeaders - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd "\live\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd "\live\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Debug" RECURSE=1 
   cd ".\os\win32"

!ENDIF 


!ENDIF 

