# Microsoft Developer Studio Generated NMAKE File, Based on gen_test_char.dsp
!IF "$(CFG)" == ""
CFG=gen_test_char - Win32 Debug
!MESSAGE No configuration specified. Defaulting to gen_test_char - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "gen_test_char - Win32 Release" && "$(CFG)" !=\
 "gen_test_char - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "gen_test_char.mak" CFG="gen_test_char - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "gen_test_char - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "gen_test_char - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
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

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

OUTDIR=.
INTDIR=.\Release
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "aprutil - Win32 Release" "apr - Win32 Release"\
 "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 ReleaseCLEAN" "aprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\gen_test_char.idb"
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(OUTDIR)\gen_test_char.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MD /W3 /O2 /I "..\include" /I "..\srclib\apr\include" /I\
 "..\srclib\apr-util\include" /I "..\os\win32" /D "WIN32" /D "NDEBUG" /D\
 "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\gen_test_char" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Release\gen_test_char.pdb" /machine:I386\
 /out:"$(OUTDIR)\gen_test_char.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj" \
	"..\srclib\apr-util\LibR\aprutil.lib" \
	"..\srclib\apr\LibR\apr.lib"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

OUTDIR=.
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\gen_test_char.exe"

!ELSE 

ALL : "aprutil - Win32 Debug" "apr - Win32 Debug" "$(OUTDIR)\gen_test_char.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"apr - Win32 DebugCLEAN" "aprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\gen_test_char.idb"
	-@erase "$(INTDIR)\gen_test_char.obj"
	-@erase "$(OUTDIR)\Debug\gen_test_char.pdb"
	-@erase "$(OUTDIR)\gen_test_char.exe"

"$(INTDIR)" :
    if not exist "$(INTDIR)/$(NULL)" mkdir "$(INTDIR)"

CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "..\include" /I\
 "..\srclib\apr\include" /I "..\srclib\apr-util\include" /I "..\os\win32" /D\
 "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\gen_test_char" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\gen_test_char.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)\Debug\gen_test_char.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\gen_test_char.exe" 
LINK32_OBJS= \
	"$(INTDIR)\gen_test_char.obj" \
	"..\srclib\apr-util\LibD\aprutil.lib" \
	"..\srclib\apr\LibD\apr.lib"

"$(OUTDIR)\gen_test_char.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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


!IF "$(CFG)" == "gen_test_char - Win32 Release" || "$(CFG)" ==\
 "gen_test_char - Win32 Debug"

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

"apr - Win32 Release" : 
   cd "..\..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Release" 
   cd "..\..\server"

"apr - Win32 ReleaseCLEAN" : 
   cd "..\..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\apr.mak" CFG="apr - Win32 Release"\
 RECURSE=1 
   cd "..\..\server"

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

"apr - Win32 Debug" : 
   cd "..\..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\apr.mak" CFG="apr - Win32 Debug" 
   cd "..\..\server"

"apr - Win32 DebugCLEAN" : 
   cd "..\..\httpd-2.0\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\apr.mak" CFG="apr - Win32 Debug" RECURSE=1\
 
   cd "..\..\server"

!ENDIF 

!IF  "$(CFG)" == "gen_test_char - Win32 Release"

"aprutil - Win32 Release" : 
   cd "..\..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Release" 
   cd "..\..\server"

"aprutil - Win32 ReleaseCLEAN" : 
   cd "..\..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\aprutil.mak" CFG="aprutil - Win32 Release"\
 RECURSE=1 
   cd "..\..\server"

!ELSEIF  "$(CFG)" == "gen_test_char - Win32 Debug"

"aprutil - Win32 Debug" : 
   cd "..\..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\aprutil.mak" CFG="aprutil - Win32 Debug" 
   cd "..\..\server"

"aprutil - Win32 DebugCLEAN" : 
   cd "..\..\httpd-2.0\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\aprutil.mak" CFG="aprutil - Win32 Debug"\
 RECURSE=1 
   cd "..\..\server"

!ENDIF 

SOURCE=.\gen_test_char.c
DEP_CPP_GEN_T=\
	"..\include\ap_config.h"\
	"..\include\ap_mmn.h"\
	"..\include\ap_release.h"\
	"..\include\httpd.h"\
	"..\include\pcreposix.h"\
	"..\os\win32\os.h"\
	"..\srclib\apr-util\include\apr_hooks.h"\
	"..\srclib\apr-util\include\apr_optional_hooks.h"\
	"..\srclib\apr-util\include\apr_uri.h"\
	"..\srclib\apr-util\include\apu.h"\
	"..\srclib\apr\include\apr.h"\
	"..\srclib\apr\include\apr_errno.h"\
	"..\srclib\apr\include\apr_file_info.h"\
	"..\srclib\apr\include\apr_file_io.h"\
	"..\srclib\apr\include\apr_general.h"\
	"..\srclib\apr\include\apr_inherit.h"\
	"..\srclib\apr\include\apr_lib.h"\
	"..\srclib\apr\include\apr_network_io.h"\
	"..\srclib\apr\include\apr_pools.h"\
	"..\srclib\apr\include\apr_sms.h"\
	"..\srclib\apr\include\apr_tables.h"\
	"..\srclib\apr\include\apr_time.h"\
	"..\srclib\apr\include\apr_user.h"\
	"..\srclib\apr\include\apr_want.h"\
	
NODEP_CPP_GEN_T=\
	"..\include\ap_config_auto.h"\
	

"$(INTDIR)\gen_test_char.obj" : $(SOURCE) $(DEP_CPP_GEN_T) "$(INTDIR)"



!ENDIF 

