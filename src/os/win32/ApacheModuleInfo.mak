# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleInfo.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleInfo - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleInfo - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleInfo - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleInfo - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleInfo.mak" CFG="ApacheModuleInfo - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleInfo - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleInfo - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheModuleInfo - Win32 Release"

OUTDIR=.\ApacheModuleInfoR
INTDIR=.\ApacheModuleInfoR
# Begin Custom Macros
OutDir=.\ApacheModuleInfoR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleInfo.dll"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\ApacheModuleInfo.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_info.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleInfo.dll"
	-@erase "$(OUTDIR)\ApacheModuleInfo.exp"
	-@erase "$(OUTDIR)\ApacheModuleInfo.lib"
	-@erase "$(OUTDIR)\ApacheModuleInfo.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /I "..\..\os\win32" /D\
 "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleInfoR/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleInfo.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleInfo.pdb" /map:"$(INTDIR)\ApacheModuleInfo.map"\
 /machine:I386 /out:"$(OUTDIR)\ApacheModuleInfo.dll"\
 /implib:"$(OUTDIR)\ApacheModuleInfo.lib" /base:@"BaseAddr.ref",mod_info 
LINK32_OBJS= \
	"$(INTDIR)\mod_info.obj" \
	"..\..\CoreR\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleInfo.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleInfo - Win32 Debug"

OUTDIR=.\ApacheModuleInfoD
INTDIR=.\ApacheModuleInfoD
# Begin Custom Macros
OutDir=.\ApacheModuleInfoD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleInfo.dll"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\ApacheModuleInfo.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_info.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleInfo.dll"
	-@erase "$(OUTDIR)\ApacheModuleInfo.exp"
	-@erase "$(OUTDIR)\ApacheModuleInfo.lib"
	-@erase "$(OUTDIR)\ApacheModuleInfo.map"
	-@erase "$(OUTDIR)\ApacheModuleInfo.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /I\
 "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleInfoD/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleInfo.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleInfo.pdb" /map:"$(INTDIR)\ApacheModuleInfo.map"\
 /debug /machine:I386 /out:"$(OUTDIR)\ApacheModuleInfo.dll"\
 /implib:"$(OUTDIR)\ApacheModuleInfo.lib" /base:@"BaseAddr.ref",mod_info 
LINK32_OBJS= \
	"$(INTDIR)\mod_info.obj" \
	"..\..\CoreD\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleInfo.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheModuleInfo - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleInfo - Win32 Debug"

!IF  "$(CFG)" == "ApacheModuleInfo - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "ApacheModuleInfo - Win32 Debug"

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

SOURCE=..\..\modules\standard\mod_info.c
DEP_CPP_MOD_I=\
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
	"..\..\include\http_main.h"\
	"..\..\include\http_protocol.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_script.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_MOD_I=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\ebcdic.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\mod_info.obj" : $(SOURCE) $(DEP_CPP_MOD_I) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

