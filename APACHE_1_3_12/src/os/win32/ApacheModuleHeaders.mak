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
OutDir=.\.\ApacheModuleHeadersR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_headers.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.dll"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.exp"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\include" /D "NDEBUG" /D "WIN32" /D\
 "_WINDOWS" /D "SHARED_MODULE" /Fp"$(INTDIR)\ApacheModuleHeaders.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleHeadersR/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleHeaders.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\ApacheModuleHeaders.pdb" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleHeaders.dll"\
 /implib:"$(OUTDIR)\ApacheModuleHeaders.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_headers.obj"

"$(OUTDIR)\ApacheModuleHeaders.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleHeaders - Win32 Debug"

OUTDIR=.\ApacheModuleHeadersD
INTDIR=.\ApacheModuleHeadersD
# Begin Custom Macros
OutDir=.\.\ApacheModuleHeadersD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleHeaders.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_headers.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.dll"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.exp"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.ilk"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.lib"
	-@erase "$(OUTDIR)\ApacheModuleHeaders.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\include" /D "_DEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "SHARED_MODULE" /Fp"$(INTDIR)\ApacheModuleHeaders.pch"\
 /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleHeadersD/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleHeaders.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:yes /pdb:"$(OUTDIR)\ApacheModuleHeaders.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)\ApacheModuleHeaders.dll"\
 /implib:"$(OUTDIR)\ApacheModuleHeaders.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_headers.obj"

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
	"..\..\include\alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\conf.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_H=\
	"..\..\include\ebcdic.h"\
	"..\..\include\os.h"\
	"..\..\include\sfio.h"\
	

"$(INTDIR)\mod_headers.obj" : $(SOURCE) $(DEP_CPP_MOD_H) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheModuleHeaders - Win32 Debug"

DEP_CPP_MOD_H=\
	"..\..\include\alloc.h"\
	"..\..\include\ap.h"\
	"..\..\include\ap_mmn.h"\
	"..\..\include\buff.h"\
	"..\..\include\conf.h"\
	"..\..\include\hsregex.h"\
	"..\..\include\http_config.h"\
	"..\..\include\httpd.h"\
	"..\..\include\util_uri.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_headers.obj" : $(SOURCE) $(DEP_CPP_MOD_H) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 


!ENDIF 

