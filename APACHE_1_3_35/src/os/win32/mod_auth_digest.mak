# Microsoft Developer Studio Generated NMAKE File, Based on mod_auth_digest.dsp
!IF "$(CFG)" == ""
CFG=mod_auth_digest - Win32 Debug
!MESSAGE No configuration specified. Defaulting to mod_auth_digest - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "mod_auth_digest - Win32 Release" && "$(CFG)" != "mod_auth_digest - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_auth_digest.mak" CFG="mod_auth_digest - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_auth_digest - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_auth_digest - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_digest.so"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\mod_auth_digest.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(INTDIR)\mod_auth_digest_src.idb"
	-@erase "$(INTDIR)\mod_auth_digest_src.pdb"
	-@erase "$(OUTDIR)\mod_auth_digest.exp"
	-@erase "$(OUTDIR)\mod_auth_digest.lib"
	-@erase "$(OUTDIR)\mod_auth_digest.pdb"
	-@erase "$(OUTDIR)\mod_auth_digest.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "..\..\include" /I "..\..\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_digest_src" /FD /c 

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
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_digest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_auth_digest.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_auth_digest.so" /implib:"$(OUTDIR)\mod_auth_digest.lib" /base:@"BaseAddr.ref",mod_auth_digest /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj" \
	"..\..\Release\ApacheCore.lib"

"$(OUTDIR)\mod_auth_digest.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_auth_digest.so"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\mod_auth_digest.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_auth_digest.obj"
	-@erase "$(INTDIR)\mod_auth_digest_src.idb"
	-@erase "$(INTDIR)\mod_auth_digest_src.pdb"
	-@erase "$(OUTDIR)\mod_auth_digest.exp"
	-@erase "$(OUTDIR)\mod_auth_digest.lib"
	-@erase "$(OUTDIR)\mod_auth_digest.pdb"
	-@erase "$(OUTDIR)\mod_auth_digest.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_auth_digest_src" /FD /c 

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
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_auth_digest.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib advapi32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_auth_digest.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_auth_digest.so" /implib:"$(OUTDIR)\mod_auth_digest.lib" /base:@"BaseAddr.ref",mod_auth_digest 
LINK32_OBJS= \
	"$(INTDIR)\mod_auth_digest.obj" \
	"..\..\Debug\ApacheCore.lib"

"$(OUTDIR)\mod_auth_digest.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_auth_digest.dep")
!INCLUDE "mod_auth_digest.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_auth_digest.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_auth_digest - Win32 Release" || "$(CFG)" == "mod_auth_digest - Win32 Debug"

!IF  "$(CFG)" == "mod_auth_digest - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "mod_auth_digest - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ENDIF 

SOURCE=..\..\modules\experimental\mod_auth_digest.c

"$(INTDIR)\mod_auth_digest.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

