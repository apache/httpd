# Microsoft Developer Studio Generated NMAKE File, Based on test.dsp
!IF "$(CFG)" == ""
CFG=test - Win32 Debug
!MESSAGE No configuration specified. Defaulting to test - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "test - Win32 Release" && "$(CFG)" != "test - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "test.mak" CFG="test - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "test - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "test - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "test - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\test.exe"

!ELSE 

ALL : "$(OUTDIR)\test.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\test.obj"
	-@erase "$(INTDIR)\test.res"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\test.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=bcc32.exe
CPP_PROJ=-s /ML -w-8057 -w-8008 -w-8066 /O2 -D"WIN32" -D"NDEBUG" -D"_WINDOWS"\
 /Fp"$(INTDIR)\test.pch" /YX -o"$(INTDIR)\\$&.obj" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.

.c.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\test.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\test.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\Release\install.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /incremental:no /pdb:"$(OUTDIR)\test.pdb" /machine:I386 /def:".\test.def"\
 /out:"$(OUTDIR)\test.exe" 
DEF_FILE= \
	".\test.def"
LINK32_OBJS= \
	"$(INTDIR)\test.obj" \
	"$(INTDIR)\test.res"

"$(OUTDIR)\test.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "test - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\test.exe"

!ELSE 

ALL : "$(OUTDIR)\test.exe"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\test.obj"
	-@erase "$(INTDIR)\test.res"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\test.exe"
	-@erase "$(OUTDIR)\test.ilk"
	-@erase "$(OUTDIR)\test.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=bcc32.exe
CPP_PROJ=-s /MLd -w-8057 -w-8008 -w-8066 /Gm -v /Od -D"WIN32" -D"_DEBUG" -D"_WINDOWS"\
 /Fp"$(INTDIR)\test.pch" /YX -o"$(INTDIR)\\$&.obj" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.

.c.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx.obj:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.c{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

MTL=midl.exe
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /o NUL /win32 
RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\test.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\test.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\Debug\install.lib wsock32.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /incremental:yes /pdb:"$(OUTDIR)\test.pdb" /debug /machine:I386\
 /def:".\test.def" /out:"$(OUTDIR)\test.exe" /pdbtype:sept 
DEF_FILE= \
	".\test.def"
LINK32_OBJS= \
	"$(INTDIR)\test.obj" \
	"$(INTDIR)\test.res"

"$(OUTDIR)\test.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "test - Win32 Release" || "$(CFG)" == "test - Win32 Debug"
SOURCE_1=.\test.c
DEP_CPP_TEST_=\
	".\test.h"\
	

"$(INTDIR)\test.obj" : $(SOURCE_0) $(DEP_CPP_TEST_) "$(INTDIR)"


SOURCE_1=.\test.rc
DEP_RSC_TEST_R=\
	".\test.h"\
	".\test.ico"\
	

"$(INTDIR)\test.res" : $(SOURCE_0) $(DEP_RSC_TEST_R) "$(INTDIR)"
	$(RSC) $(RSC_PROJ) $(SOURCE_0)



!ENDIF 

