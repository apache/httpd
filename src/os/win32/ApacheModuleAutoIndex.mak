# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=ApacheModuleAutoIndex - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to ApacheModuleAutoIndex -\
 Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleAutoIndex - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleAutoIndex - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleAutoIndex.mak"\
 CFG="ApacheModuleAutoIndex - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleAutoIndex - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleAutoIndex - Win32 Debug" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 
################################################################################
# Begin Project
# PROP Target_Last_Scanned "ApacheModuleAutoIndex - Win32 Debug"
MTL=mktyplib.exe
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "AutoIndexR"
# PROP Intermediate_Dir "AutoIndexR"
# PROP Target_Dir ""
OUTDIR=.\AutoIndexR
INTDIR=.\AutoIndexR

ALL : "$(OUTDIR)\ApacheModuleAutoIndex.dll"

CLEAN : 
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.dll"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.exp"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\regex" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\regex" /D "WIN32" /D "NDEBUG" /D\
 "_WINDOWS" /Fp"$(INTDIR)/ApacheModuleAutoIndex.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\AutoIndexR/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheModuleAutoIndex.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
LINK32_FLAGS=..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/ApacheModuleAutoIndex.pdb" /machine:I386\
 /out:"$(OUTDIR)/ApacheModuleAutoIndex.dll"\
 /implib:"$(OUTDIR)/ApacheModuleAutoIndex.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_autoindex.obj"

"$(OUTDIR)\ApacheModuleAutoIndex.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "AutoIndexD"
# PROP Intermediate_Dir "AutoIndexD"
# PROP Target_Dir ""
OUTDIR=.\AutoIndexD
INTDIR=.\AutoIndexD

ALL : "$(OUTDIR)\ApacheModuleAutoIndex.dll"

CLEAN : 
	-@erase "$(INTDIR)\mod_autoindex.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.dll"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.exp"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.ilk"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.lib"
	-@erase "$(OUTDIR)\ApacheModuleAutoIndex.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\regex" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\regex" /D "WIN32" /D "_DEBUG"\
 /D "_WINDOWS" /Fp"$(INTDIR)/ApacheModuleAutoIndex.pch" /YX /Fo"$(INTDIR)/"\
 /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\AutoIndexD/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheModuleAutoIndex.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 ..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
LINK32_FLAGS=..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)/ApacheModuleAutoIndex.pdb" /debug\
 /machine:I386 /out:"$(OUTDIR)/ApacheModuleAutoIndex.dll"\
 /implib:"$(OUTDIR)/ApacheModuleAutoIndex.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_autoindex.obj"

"$(OUTDIR)\ApacheModuleAutoIndex.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 

.c{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_OBJS)}.obj:
   $(CPP) $(CPP_PROJ) $<  

.c{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cpp{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

.cxx{$(CPP_SBRS)}.sbr:
   $(CPP) $(CPP_PROJ) $<  

################################################################################
# Begin Target

# Name "ApacheModuleAutoIndex - Win32 Release"
# Name "ApacheModuleAutoIndex - Win32 Debug"

!IF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Release"

!ELSEIF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=\work\apache\src\mod_autoindex.c

!IF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Release"

DEP_CPP_MOD_A=\
	"..\alloc.h"\
	"..\buff.h"\
	"..\conf.h"\
	"..\http_config.h"\
	"..\http_core.h"\
	"..\http_log.h"\
	"..\http_main.h"\
	"..\http_protocol.h"\
	"..\http_request.h"\
	"..\httpd.h"\
	"..\regex\regex.h"\
	"..\util_script.h"\
	".\readdir.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_A=\
	"..\sfio.h"\
	

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ELSEIF  "$(CFG)" == "ApacheModuleAutoIndex - Win32 Debug"

DEP_CPP_MOD_A=\
	"..\alloc.h"\
	"..\buff.h"\
	"..\conf.h"\
	"..\http_config.h"\
	"..\http_core.h"\
	"..\http_log.h"\
	"..\http_main.h"\
	"..\http_protocol.h"\
	"..\http_request.h"\
	"..\httpd.h"\
	"..\util_script.h"\
	".\readdir.h"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	
NODEP_CPP_MOD_A=\
	"..\sfio.h"\
	

"$(INTDIR)\mod_autoindex.obj" : $(SOURCE) $(DEP_CPP_MOD_A) "$(INTDIR)"
   $(CPP) $(CPP_PROJ) $(SOURCE)


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
