# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

!IF "$(CFG)" == ""
CFG=regex - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to regex - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "regex - Win32 Release" && "$(CFG)" != "regex - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "regex.mak" CFG="regex - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "regex - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "regex - Win32 Debug" (based on "Win32 (x86) Static Library")
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
# PROP Target_Last_Scanned "regex - Win32 Debug"
CPP=cl.exe

!IF  "$(CFG)" == "regex - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\regex.lib"

CLEAN : 
	-@erase "$(INTDIR)\regcomp.obj"
	-@erase "$(INTDIR)\regerror.obj"
	-@erase "$(INTDIR)\regexec.obj"
	-@erase "$(INTDIR)\regfree.obj"
	-@erase "$(OUTDIR)\regex.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "." /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "." /D "WIN32" /D "NDEBUG" /D "_WINDOWS"\
 /Fp"$(INTDIR)/regex.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/regex.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/regex.lib" 
LIB32_OBJS= \
	"$(INTDIR)\regcomp.obj" \
	"$(INTDIR)\regerror.obj" \
	"$(INTDIR)\regexec.obj" \
	"$(INTDIR)\regfree.obj"

"$(OUTDIR)\regex.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "regex - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\regex.lib" "$(OUTDIR)\regex.bsc"

CLEAN : 
	-@erase "$(INTDIR)\regcomp.obj"
	-@erase "$(INTDIR)\regcomp.sbr"
	-@erase "$(INTDIR)\regerror.obj"
	-@erase "$(INTDIR)\regerror.sbr"
	-@erase "$(INTDIR)\regexec.obj"
	-@erase "$(INTDIR)\regexec.sbr"
	-@erase "$(INTDIR)\regfree.obj"
	-@erase "$(INTDIR)\regfree.sbr"
	-@erase "$(OUTDIR)\regex.bsc"
	-@erase "$(OUTDIR)\regex.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "." /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FR /YX /c
CPP_PROJ=/nologo /MDd /W3 /GX /Z7 /Od /I "." /D "WIN32" /D "_DEBUG" /D\
 "_WINDOWS" /FR"$(INTDIR)/" /Fp"$(INTDIR)/regex.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\Debug/
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/regex.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\regcomp.sbr" \
	"$(INTDIR)\regerror.sbr" \
	"$(INTDIR)\regexec.sbr" \
	"$(INTDIR)\regfree.sbr"

"$(OUTDIR)\regex.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/regex.lib" 
LIB32_OBJS= \
	"$(INTDIR)\regcomp.obj" \
	"$(INTDIR)\regerror.obj" \
	"$(INTDIR)\regexec.obj" \
	"$(INTDIR)\regfree.obj"

"$(OUTDIR)\regex.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
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

# Name "regex - Win32 Release"
# Name "regex - Win32 Debug"

!IF  "$(CFG)" == "regex - Win32 Release"

!ELSEIF  "$(CFG)" == "regex - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\regcomp.c
DEP_CPP_REGCO=\
	".\cclass.h"\
	".\cname.h"\
	".\regcomp.ih"\
	".\regex.h"\
	".\regex2.h"\
	".\utils.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

!IF  "$(CFG)" == "regex - Win32 Release"


"$(INTDIR)\regcomp.obj" : $(SOURCE) $(DEP_CPP_REGCO) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "regex - Win32 Debug"


"$(INTDIR)\regcomp.obj" : $(SOURCE) $(DEP_CPP_REGCO) "$(INTDIR)"

"$(INTDIR)\regcomp.sbr" : $(SOURCE) $(DEP_CPP_REGCO) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\regerror.c
DEP_CPP_REGER=\
	".\regerror.ih"\
	".\regex.h"\
	".\utils.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

!IF  "$(CFG)" == "regex - Win32 Release"


"$(INTDIR)\regerror.obj" : $(SOURCE) $(DEP_CPP_REGER) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "regex - Win32 Debug"


"$(INTDIR)\regerror.obj" : $(SOURCE) $(DEP_CPP_REGER) "$(INTDIR)"

"$(INTDIR)\regerror.sbr" : $(SOURCE) $(DEP_CPP_REGER) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\regexec.c
DEP_CPP_REGEX=\
	".\engine.c"\
	".\engine.ih"\
	".\regex.h"\
	".\regex2.h"\
	".\utils.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

!IF  "$(CFG)" == "regex - Win32 Release"


"$(INTDIR)\regexec.obj" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "regex - Win32 Debug"


"$(INTDIR)\regexec.obj" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"

"$(INTDIR)\regexec.sbr" : $(SOURCE) $(DEP_CPP_REGEX) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\regfree.c
DEP_CPP_REGFR=\
	".\regex.h"\
	".\regex2.h"\
	".\utils.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

!IF  "$(CFG)" == "regex - Win32 Release"


"$(INTDIR)\regfree.obj" : $(SOURCE) $(DEP_CPP_REGFR) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "regex - Win32 Debug"


"$(INTDIR)\regfree.obj" : $(SOURCE) $(DEP_CPP_REGFR) "$(INTDIR)"

"$(INTDIR)\regfree.sbr" : $(SOURCE) $(DEP_CPP_REGFR) "$(INTDIR)"


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
