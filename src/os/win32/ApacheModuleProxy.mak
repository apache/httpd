# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

!IF "$(CFG)" == ""
CFG=ApacheModuleProxy - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to ApacheModuleProxy - Win32\
 Debug.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleProxy - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleProxy - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleProxy.mak" CFG="ApacheModuleProxy - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ApacheModuleProxy - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "ApacheModuleProxy - Win32 Debug" (based on\
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
# PROP Target_Last_Scanned "ApacheModuleProxy - Win32 Debug"
MTL=mktyplib.exe
RSC=rc.exe
CPP=cl.exe

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "ApacheMo"
# PROP BASE Intermediate_Dir "ApacheMo"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

CLEAN : 
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(OUTDIR)\ApacheModuleProxy.dll"
	-@erase "$(OUTDIR)\ApacheModuleProxy.exp"
	-@erase "$(OUTDIR)\ApacheModuleProxy.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\.." /I "..\..\regex" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\.." /I "..\..\regex" /D "WIN32" /D\
 "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)/ApacheModuleProxy.pch" /YX /Fo"$(INTDIR)/"\
 /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /win32
MTL_PROJ=/nologo /D "NDEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "NDEBUG"
# ADD RSC /l 0x809 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheModuleProxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 ..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /machine:I386
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)/ApacheModuleProxy.pdb" /machine:I386\
 /out:"$(OUTDIR)/ApacheModuleProxy.dll"\
 /implib:"$(OUTDIR)/ApacheModuleProxy.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj"

"$(OUTDIR)\ApacheModuleProxy.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "ApacheM0"
# PROP BASE Intermediate_Dir "ApacheM0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
OUTDIR=.\Debug
INTDIR=.\Debug

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

CLEAN : 
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(INTDIR)\vc40.idb"
	-@erase "$(INTDIR)\vc40.pdb"
	-@erase "$(OUTDIR)\ApacheModuleProxy.dll"
	-@erase "$(OUTDIR)\ApacheModuleProxy.exp"
	-@erase "$(OUTDIR)\ApacheModuleProxy.ilk"
	-@erase "$(OUTDIR)\ApacheModuleProxy.lib"
	-@erase "$(OUTDIR)\ApacheModuleProxy.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /I "..\..\regex" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\.." /I "..\..\regex" /D\
 "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"$(INTDIR)/ApacheModuleProxy.pch" /YX\
 /Fo"$(INTDIR)/" /Fd"$(INTDIR)/" /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\.
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /win32
MTL_PROJ=/nologo /D "_DEBUG" /win32 
# ADD BASE RSC /l 0x809 /d "_DEBUG"
# ADD RSC /l 0x809 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/ApacheModuleProxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386
# ADD LINK32 ..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll /debug /machine:I386
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)/ApacheModuleProxy.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)/ApacheModuleProxy.dll"\
 /implib:"$(OUTDIR)/ApacheModuleProxy.lib" 
LINK32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj"

"$(OUTDIR)\ApacheModuleProxy.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
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

# Name "ApacheModuleProxy - Win32 Release"
# Name "ApacheModuleProxy - Win32 Debug"

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\proxy_util.c
DEP_CPP_PROXY=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\md5.h"\
	"..\..\multithread.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_PROXY=\
	"..\..\sfio.h"\
	

"$(INTDIR)\proxy_util.obj" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_cache.c

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

DEP_CPP_PROXY_=\
	"..\..\conf.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\httpd.h"\
	"..\..\md5.h"\
	"..\..\multithread.h"\
	"..\..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\types.h"\
	{$(INCLUDE)}"\sys\utime.h"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

DEP_CPP_PROXY_=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\md5.h"\
	"..\..\multithread.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	"..\..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	{$(INCLUDE)}"\sys\utime.h"\
	
NODEP_CPP_PROXY_=\
	"..\..\sfio.h"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_connect.c
DEP_CPP_PROXY_C=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_PROXY_C=\
	"..\..\sfio.h"\
	

"$(INTDIR)\proxy_connect.obj" : $(SOURCE) $(DEP_CPP_PROXY_C) "$(INTDIR)"


# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_ftp.c

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

DEP_CPP_PROXY_F=\
	"..\..\conf.h"\
	"..\..\http_main.h"\
	"..\..\httpd.h"\
	"..\..\mod_mime.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

DEP_CPP_PROXY_F=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_main.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\mod_mime.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_PROXY_F=\
	"..\..\sfio.h"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_http.c

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

DEP_CPP_PROXY_H=\
	"..\..\conf.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\httpd.h"\
	"..\..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\types.h"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

DEP_CPP_PROXY_H=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_main.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	"..\..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_PROXY_H=\
	"..\..\sfio.h"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_proxy.c

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

DEP_CPP_MOD_P=\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "ApacheModuleProxy - Win32 Debug"

DEP_CPP_MOD_P=\
	"..\..\alloc.h"\
	"..\..\buff.h"\
	"..\..\conf.h"\
	"..\..\explain.h"\
	"..\..\http_config.h"\
	"..\..\http_log.h"\
	"..\..\http_protocol.h"\
	"..\..\httpd.h"\
	"..\..\nt\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\stat.h"\
	{$(INCLUDE)}"\sys\types.h"\
	
NODEP_CPP_MOD_P=\
	"..\..\sfio.h"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
