# Microsoft Developer Studio Generated NMAKE File, Based on install.dsp
!IF "$(CFG)" == ""
CFG=install - Win32 Debug
!MESSAGE No configuration specified. Defaulting to install - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "install - Win32 Release" && "$(CFG)" !=\
 "install - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "install.mak" CFG="install - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "install - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "install - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "install - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\install.dll"

!ELSE 

ALL : "$(OUTDIR)\install.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\install.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\install.dll"
	-@erase "$(OUTDIR)\install.exp"
	-@erase "$(OUTDIR)\install.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "../../../../include" /D "WIN32" /D\
 "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\install.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\install.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\install.pdb" /machine:I386 /def:".\install.def"\
 /out:"$(OUTDIR)\install.dll" /implib:"$(OUTDIR)\install.lib" 
DEF_FILE= \
	".\install.def"
LINK32_OBJS= \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\install.obj"

"$(OUTDIR)\install.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "install - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\install.dll"

!ELSE 

ALL : "$(OUTDIR)\install.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\ap_snprintf.obj"
	-@erase "$(INTDIR)\install.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\install.dll"
	-@erase "$(OUTDIR)\install.exp"
	-@erase "$(OUTDIR)\install.ilk"
	-@erase "$(OUTDIR)\install.lib"
	-@erase "$(OUTDIR)\install.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MTd /W3 /Gm /GX /Zi /Od /I "../../../../include" /D "WIN32"\
 /D "_DEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\install.pch" /YX /Fo"$(INTDIR)\\"\
 /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\install.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib\
 advapi32.lib shell32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)\install.pdb" /debug /machine:I386\
 /def:".\install.def" /out:"$(OUTDIR)\install.dll"\
 /implib:"$(OUTDIR)\install.lib" /pdbtype:sept 
DEF_FILE= \
	".\install.def"
LINK32_OBJS= \
	"$(INTDIR)\ap_snprintf.obj" \
	"$(INTDIR)\install.obj"

"$(OUTDIR)\install.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "install - Win32 Release" || "$(CFG)" ==\
 "install - Win32 Debug"
SOURCE=..\..\..\..\ap\ap_snprintf.c

!IF  "$(CFG)" == "install - Win32 Release"

DEP_CPP_AP_SN=\
	"..\..\..\..\include\alloc.h"\
	"..\..\..\..\include\ap.h"\
	"..\..\..\..\include\ap_config.h"\
	"..\..\..\..\include\ap_ctype.h"\
	"..\..\..\..\include\ap_mmn.h"\
	"..\..\..\..\include\buff.h"\
	"..\..\..\..\include\hsregex.h"\
	"..\..\..\..\include\httpd.h"\
	"..\..\..\..\include\util_uri.h"\
	"..\..\os.h"\
	"..\..\readdir.h"\
	

"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) $(DEP_CPP_AP_SN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "install - Win32 Debug"

DEP_CPP_AP_SN=\
	"..\..\..\..\include\alloc.h"\
	"..\..\..\..\include\ap.h"\
	"..\..\..\..\include\ap_config.h"\
	"..\..\..\..\include\ap_ctype.h"\
	"..\..\..\..\include\ap_mmn.h"\
	"..\..\..\..\include\buff.h"\
	"..\..\..\..\include\hsregex.h"\
	"..\..\..\..\include\httpd.h"\
	"..\..\..\..\include\util_uri.h"\
	"..\..\os.h"\
	"..\..\readdir.h"\
	

"$(INTDIR)\ap_snprintf.obj" : $(SOURCE) $(DEP_CPP_AP_SN) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

SOURCE=.\install.c

!IF  "$(CFG)" == "install - Win32 Release"

DEP_CPP_INSTA=\
	"..\..\..\..\include\ap.h"\
	"..\..\..\..\include\ap_config.h"\
	"..\..\..\..\include\ap_ctype.h"\
	"..\..\..\..\include\ap_mmn.h"\
	"..\..\..\..\include\conf.h"\
	"..\..\..\..\include\hsregex.h"\
	"..\..\os.h"\
	

"$(INTDIR)\install.obj" : $(SOURCE) $(DEP_CPP_INSTA) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "install - Win32 Debug"

DEP_CPP_INSTA=\
	"..\..\..\..\include\ap.h"\
	"..\..\..\..\include\ap_config.h"\
	"..\..\..\..\include\ap_ctype.h"\
	"..\..\..\..\include\ap_mmn.h"\
	"..\..\..\..\include\conf.h"\
	"..\..\..\..\include\hsregex.h"\
	"..\..\os.h"\
	

"$(INTDIR)\install.obj" : $(SOURCE) $(DEP_CPP_INSTA) "$(INTDIR)"


!ENDIF 


!ENDIF 

