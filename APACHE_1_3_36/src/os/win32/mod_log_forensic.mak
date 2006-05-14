# Microsoft Developer Studio Generated NMAKE File, Based on mod_log_forensic.dsp
!IF "$(CFG)" == ""
CFG=mod_log_forensic - Win32 Release
!MESSAGE No configuration specified. Defaulting to mod_log_forensic - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "mod_log_forensic - Win32 Release" && "$(CFG)" != "mod_log_forensic - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "mod_log_forensic.mak" CFG="mod_log_forensic - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "mod_log_forensic - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "mod_log_forensic - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "mod_log_forensic - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_log_forensic.so"

!ELSE 

ALL : "ApacheCore - Win32 Release" "$(OUTDIR)\mod_log_forensic.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_log_forensic.obj"
	-@erase "$(INTDIR)\mod_log_forensic_src.idb"
	-@erase "$(INTDIR)\mod_log_forensic_src.pdb"
	-@erase "$(OUTDIR)\mod_log_forensic.exp"
	-@erase "$(OUTDIR)\mod_log_forensic.lib"
	-@erase "$(OUTDIR)\mod_log_forensic.pdb"
	-@erase "$(OUTDIR)\mod_log_forensic.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /Zi /O2 /Oy- /I "..\..\include" /I "..\..\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_log_forensic_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_log_forensic.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_log_forensic.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_log_forensic.so" /implib:"$(OUTDIR)\mod_log_forensic.lib" /base:@"BaseAddr.ref",mod_log_forensic /opt:ref 
LINK32_OBJS= \
	"$(INTDIR)\mod_log_forensic.obj" \
	"..\..\Release\ApacheCore.lib"

"$(OUTDIR)\mod_log_forensic.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "mod_log_forensic - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\mod_log_forensic.so"

!ELSE 

ALL : "ApacheCore - Win32 Debug" "$(OUTDIR)\mod_log_forensic.so"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"ApacheCore - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\mod_log_forensic.obj"
	-@erase "$(INTDIR)\mod_log_forensic_src.idb"
	-@erase "$(INTDIR)\mod_log_forensic_src.pdb"
	-@erase "$(OUTDIR)\mod_log_forensic.exp"
	-@erase "$(OUTDIR)\mod_log_forensic.lib"
	-@erase "$(OUTDIR)\mod_log_forensic.pdb"
	-@erase "$(OUTDIR)\mod_log_forensic.so"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\..\include" /I "..\..\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\mod_log_forensic_src" /FD /c 

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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\mod_log_forensic.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\mod_log_forensic.pdb" /debug /machine:I386 /out:"$(OUTDIR)\mod_log_forensic.so" /implib:"$(OUTDIR)\mod_log_forensic.lib" /base:@"BaseAddr.ref",mod_log_forensic 
LINK32_OBJS= \
	"$(INTDIR)\mod_log_forensic.obj" \
	"..\..\Debug\ApacheCore.lib"

"$(OUTDIR)\mod_log_forensic.so" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(NO_EXTERNAL_DEPS)" != "1"
!IF EXISTS("mod_log_forensic.dep")
!INCLUDE "mod_log_forensic.dep"
!ELSE 
!MESSAGE Warning: cannot find "mod_log_forensic.dep"
!ENDIF 
!ENDIF 


!IF "$(CFG)" == "mod_log_forensic - Win32 Release" || "$(CFG)" == "mod_log_forensic - Win32 Debug"

!IF  "$(CFG)" == "mod_log_forensic - Win32 Release"

"ApacheCore - Win32 Release" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" 
   cd ".\os\win32"

"ApacheCore - Win32 ReleaseCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Release" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ELSEIF  "$(CFG)" == "mod_log_forensic - Win32 Debug"

"ApacheCore - Win32 Debug" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" 
   cd ".\os\win32"

"ApacheCore - Win32 DebugCLEAN" : 
   cd ".\..\.."
   $(MAKE) /$(MAKEFLAGS) /F ".\ApacheCore.mak" CFG="ApacheCore - Win32 Debug" RECURSE=1 CLEAN 
   cd ".\os\win32"

!ENDIF 

SOURCE=..\..\modules\standard\mod_log_forensic.c

"$(INTDIR)\mod_log_forensic.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

