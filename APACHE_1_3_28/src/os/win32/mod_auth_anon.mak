# Microsoft Developer Studio Generated NMAKE File, Based on mod_auth_anon.dsp
!IF "$(CFG)" == ""
CFG=mod_auth_anon - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_auth_anon - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_auth_anon - Win32 Release" && "$(CFG)" != "mod_auth_anon - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_auth_anon.mak" CFG="mod_auth_anon - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_auth_anon - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_auth_anon - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_auth_anon - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_anon.so"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\mod_auth_anon.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_anon.obj"
	-@erase "$(INTDIR)\mod_auth_anon_src.idb"
	-@erase "$(INTDIR)\mod_auth_anon_src.pdb"
	-@erase "$(OUTDIR)\mod_auth_anon.exp"
	-@erase "$(OUTDIR)\mod_auth_anon.lib"
	-@erase "$(OUTDIR)\mod_auth_anon.pdb"
	-@erase "$(OUTDIR)\mod_auth_anon.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /I "..\..\include" /I "..\..\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_anon_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_anon.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_auth_anon.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_auth_anon.so" /implib:"$(OUTDIR)\mod_auth_anon.lib" /base:@"BaseAddr.ref",mod_auth_anon /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_anon.obj" \
	"..\..\Release\ApacheCore.lib"

"$(OUTDIR)\mod_auth_anon.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_auth_anon - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_anon.so"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\mod_auth_anon.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_anon.obj"
	-@erase "$(INTDIR)\mod_auth_anon_src.idb"
	-@erase "$(INTDIR)\mod_auth_anon_src.pdb"
	-@erase "$(OUTDIR)\mod_auth_anon.exp"
	-@erase "$(OUTDIR)\mod_auth_anon.lib"
	-@erase "$(OUTDIR)\mod_auth_anon.pdb"
	-@erase "$(OUTDIR)\mod_auth_anon.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_anon_src" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(INTDIR)}.sbr::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_anon.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_auth_anon.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_auth_anon.so" /implib:"$(OUTDIR)\mod_auth_anon.lib" /base:@"BaseAddr.ref",mod_auth_anon 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_anon.obj" \
	"..\..\Debug\ApacheCore.lib"

"$(OUTDIR)\mod_auth_anon.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_auth_anon.dep")
!INCLUDE "mod_auth_anon.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_auth_anon.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_auth_anon - Win32 Release" || "$(CFG)" == "mod_auth_anon - Win32 Debug"

!IF  "$(CFG)" == "mod_auth_anon - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "mod_auth_anon - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd "..\../..\src"
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ENDIF 

SOURCE=..\..\modules\standard\mod_auth_anon.c

"$(INTDIR)\mod_auth_anon.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

