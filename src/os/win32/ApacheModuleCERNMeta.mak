# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleCERNMeta.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleCERNMeta - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleCERNMeta - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleCERNMeta - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleCERNMeta - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleCERNMeta.mak"\
 CFG="ApacheModuleCERNMeta - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleCERNMeta - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleCERNMeta - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "ApacheModuleCERNMeta - Win32 Release"

OUTDIR=.\ApacheModuleCERNMetaR
INTDIR=.\ApacheModuleCERNMetaR
# Begin Custom Macros
OutDir=.\.\ApacheModuleCERNMetaR
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleCERNMeta.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleCERNMeta.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_cern_meta.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.dll"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.exp"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\ap" /I "..\..\regex" /I "..\..\main"\
 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\ApacheModuleCERNMeta.pch"\
 /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\ApacheModuleCERNMetaR/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleCERNMeta.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:no /pdb:"$(OUTDIR)\ApacheModuleCERNMeta.pdb" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleCERNMeta.dll"\
 /implib:"$(OUTDIR)\ApacheModuleCERNMeta.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_cern_meta.obj"

"$(OUTDIR)\ApacheModuleCERNMeta.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleCERNMeta - Win32 Debug"

OUTDIR=.\ApacheModuleCERNMetaD
INTDIR=.\ApacheModuleCERNMetaD
# Begin Custom Macros
OutDir=.\.\ApacheModuleCERNMetaD
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleCERNMeta.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleCERNMeta.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_cern_meta.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.dll"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.exp"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.ilk"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.lib"
	-@erase "$(OUTDIR)\ApacheModuleCERNMeta.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\ap" /I "..\..\regex" /I\
 "..\..\main" /D "WIN32" /D "_DEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)\ApacheModuleCERNMeta.pch" /YX /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\"\
 /FD /c 
CPP_OBJS=.\ApacheModuleCERNMetaD/
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
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleCERNMeta.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib /nologo /subsystem:windows\
 /dll /incremental:yes /pdb:"$(OUTDIR)\ApacheModuleCERNMeta.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)\ApacheModuleCERNMeta.dll"\
 /implib:"$(OUTDIR)\ApacheModuleCERNMeta.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_cern_meta.obj"

"$(OUTDIR)\ApacheModuleCERNMeta.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "ApacheModuleCERNMeta - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleCERNMeta - Win32 Debug"
SOURCE=..\..\modules\standard\mod_cern_meta.c

!IF  "$(CFG)" == "ApacheModuleCERNMeta - Win32 Release"

DEP_CPP_MOD_C=\
	"..\..\ap\ap.h"\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_request.h"\
	"..\..\main\httpd.h"\
	"..\..\main\util_script.h"\
	"..\..\regex\regex.h"\
	".\os.h"\
	".\readdir.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_C=\
	"..\..\main\ebcdic.h"\
	"..\..\main\os.h"\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\mod_cern_meta.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheModuleCERNMeta - Win32 Debug"

DEP_CPP_MOD_C=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_request.h"\
	"..\..\main\httpd.h"\
	"..\..\main\util_script.h"\
	"..\..\regex\regex.h"\
	".\os.h"\
	".\readdir.h"\
	

"$(INTDIR)\mod_cern_meta.obj" : $(SOURCE) $(DEP_CPP_MOD_C) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 


!ENDIF 

