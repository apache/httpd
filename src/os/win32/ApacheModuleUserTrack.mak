# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleUserTrack.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleUserTrack - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleUserTrack -\
 Win32 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleUserTrack - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleUserTrack - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleUserTrack.mak"\
 CFG="ApacheModuleUserTrack - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleUserTrack - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleUserTrack - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheModuleUserTrack - Win32 Release"

OUTDIR=.\ApacheModuleUserTrackR
INTDIR=.\ApacheModuleUserTrackR
# Begin Custom Macros
OutDir=.\ApacheModuleUserTrackR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleUserTrack.dll"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\ApacheModuleUserTrack.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_usertrack.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.dll"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.exp"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.lib"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /I "..\..\os\win32" /D\
 "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleUserTrackR/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleUserTrack.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleUserTrack.pdb"\
 /map:"$(INTDIR)\ApacheModuleUserTrack.map" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleUserTrack.dll"\
 /implib:"$(OUTDIR)\ApacheModuleUserTrack.lib"\
 /base:@"BaseAddr.ref",mod_usertrack 
LINK32_OBJS= \
	"$(INTDIR)\mod_usertrack.obj" \
	"..\..\CoreR\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleUserTrack.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleUserTrack - Win32 Debug"

OUTDIR=.\ApacheModuleUserTrackD
INTDIR=.\ApacheModuleUserTrackD
# Begin Custom Macros
OutDir=.\ApacheModuleUserTrackD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleUserTrack.dll"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\ApacheModuleUserTrack.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_usertrack.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.dll"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.exp"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.lib"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.map"
	-@erase "$(OUTDIR)\ApacheModuleUserTrack.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /I\
 "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleUserTrackD/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleUserTrack.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no\
 /pdb:"$(OUTDIR)\ApacheModuleUserTrack.pdb"\
 /map:"$(INTDIR)\ApacheModuleUserTrack.map" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleUserTrack.dll"\
 /implib:"$(OUTDIR)\ApacheModuleUserTrack.lib"\
 /base:@"BaseAddr.ref",mod_usertrack 
LINK32_OBJS= \
	"$(INTDIR)\mod_usertrack.obj" \
	"..\..\CoreD\ApacheCore.lib"

"$(OUTDIR)\ApacheModuleUserTrack.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheModuleUserTrack - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleUserTrack - Win32 Debug"

!IF  "$(CFG)" == "ApacheModuleUserTrack - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release"\
 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "\apache\apache-1.3\src"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\ApacheCore.mak"\
 CFG="ApacheCore - Win32 Release" RECURSE=1 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "ApacheModuleUserTrack - Win32 Debug"

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

SOURCE=..\..\modules\standard\mod_usertrack.c
DEP_CPP_MOD_U=\
	"..\..\include\ap.h"\
	"..\..\include\ap_alloc.h"\
	"..\..\include\ap_config.h"\
	"..\..\include\ap_ctype.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\http_core.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	
NODEP_CPP_MOD_U=\
	"..\..\include\ap_config_auto.h"\
	"..\..\include\ebcdic.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\mod_usertrack.obj" : $(SOURCE) $(DEP_CPP_MOD_U) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

