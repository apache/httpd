# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

!IF "$(CFG)" == ""
CFG=ApacheLaunch - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to ApacheLaunch - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheLaunch - Win32 Release" && "$(CFG)" !=\
 "ApacheLaunch - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheLaunch.mak" CFG="ApacheLaunch - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheLaunch - Win32 Release" (based on\
 "Win32 (x86) Console Application")
!MESSAGE "ApacheLaunch - Win32 Debug" (based on\
 "Win32 (x86) Console Application")
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
# PROP Target_Last_Scanned "ApacheLaunch - Win32 Debug"
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheLaunch - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ApacheLa"
# PROP BASE Intermediate_Dir "ApacheLa"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LaunchR"
# PROP Intermediate_Dir "LaunchR"
# PROP Target_Dir ""
OUTDIR=.\LaunchR
INTDIR=.\LaunchR

ALL : "$(OUTDIR)\ApacheLaunch.exe"

CLEAN : 
	-@erase "$(INTDIR)\dummy.obj"
	-@erase "$(OUTDIR)\ApacheLaunch.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/ApacheLaunch.pch" /YX /Fo"$(INTDIR)/" /c 
CPP_OBJS=.\LaunchR/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheLaunch.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
LINK32_FLAGS=CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:no\
 /pdb:"$(OUTDIR)/ApacheLaunch.pdb" /machine:I386\
 /out:"$(OUTDIR)/ApacheLaunch.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dummy.obj"

"$(OUTDIR)\ApacheLaunch.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheLaunch - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ApacheL0"
# PROP BASE Intermediate_Dir "ApacheL0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LaunchD"
# PROP Intermediate_Dir "LaunchD"
# PROP Target_Dir ""
OUTDIR=.\LaunchD
INTDIR=.\LaunchD

ALL : "$(OUTDIR)\ApacheLaunch.exe"

CLEAN : 
	-@erase "$(INTDIR)\dummy.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\ApacheLaunch.exe"
	-@erase "$(OUTDIR)\ApacheLaunch.ilk"
	-@erase "$(OUTDIR)\ApacheLaunch.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /YX /c
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE"\
 /Fp"$(INTDIR)/ApacheLaunch.pch" /YX /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\LaunchD/
CPP_SBRS=.\.
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheLaunch.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
# ADD LINK32 CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386
LINK32_FLAGS=CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /incremental:yes\
 /pdb:"$(OUTDIR)/ApacheLaunch.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)/ApacheLaunch.exe" 
LINK32_OBJS= \
	"$(INTDIR)\dummy.obj"

"$(OUTDIR)\ApacheLaunch.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "ApacheLaunch - Win32 Release"
# Name "ApacheLaunch - Win32 Debug"

!IF  "$(CFG)" == "ApacheLaunch - Win32 Release"

!ELSEIF  "$(CFG)" == "ApacheLaunch - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\dummy.c

"$(INTDIR)\dummy.obj" : $(SOURCE) "$(INTDIR)"


# End Source File
# End Target
# End Project
################################################################################
