# Microsoft Developer Studio Generated NMAKE File, Format Version 4.20
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

!IF "$(CFG)" == ""
CFG=proxy - Win32 Debug
!MESSAGE No configuration specified.  Defaulting to proxy - Win32 Debug.
!ENDIF 

!IF "$(CFG)" != "proxy - Win32 Release" && "$(CFG)" != "proxy - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE on this makefile
!MESSAGE by defining the macro CFG on the command line.  For example:
!MESSAGE 
!MESSAGE NMAKE /f "proxy.mak" CFG="proxy - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "proxy - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "proxy - Win32 Debug" (based on "Win32 (x86) Static Library")
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
# PROP Target_Last_Scanned "proxy - Win32 Debug"
CPP=cl.exe

!IF  "$(CFG)" == "proxy - Win32 Release"

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

ALL : "$(OUTDIR)\proxy.lib"

CLEAN : 
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(OUTDIR)\proxy.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MT /W3 /GX /O2 /I "../.." /I "../../regex" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "VALICERT" /YX /I /cryptosoft/server/urlscreen" /I /cryptosoft/server/urlscreen" " " /c
CPP_PROJ=/nologo /MT /W3 /GX /O2 /I "../.." /I "../../regex" /D "NDEBUG" /D\
 "WIN32" /D "_WINDOWS" /D "VALICERT" /Fp"$(INTDIR)/proxy.pch" /YX\
 /Fo"$(INTDIR)/" /I\
 /cryptosoft/server/urlscreen" /I /cryptosoft/server/urlscreen" " " /c 
CPP_OBJS=.\Release/
CPP_SBRS=.\.
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/proxy.bsc" 
BSC32_SBRS= \
	
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/proxy.lib" 
LIB32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj"

"$(OUTDIR)\proxy.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
    $(LIB32) @<<
  $(LIB32_FLAGS) $(DEF_FLAGS) $(LIB32_OBJS)
<<

!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

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

ALL : "$(OUTDIR)\proxy.lib" "$(OUTDIR)\proxy.bsc"

CLEAN : 
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\mod_proxy.sbr"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_cache.sbr"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_connect.sbr"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_ftp.sbr"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_http.sbr"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(INTDIR)\proxy_util.sbr"
	-@erase "$(OUTDIR)\proxy.bsc"
	-@erase "$(OUTDIR)\proxy.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /c
# ADD CPP /nologo /MTd /W3 /GX /Z7 /Od /I "../.." /I "../../regex" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "VALICERT" /FR /YX /I /cryptosoft/server/urlscreen" /I /cryptosoft/server/urlscreen" " " /c
CPP_PROJ=/nologo /MTd /W3 /GX /Z7 /Od /I "../.." /I "../../regex" /D "_DEBUG"\
 /D "WIN32" /D "_WINDOWS" /D "VALICERT" /FR"$(INTDIR)/" /Fp"$(INTDIR)/proxy.pch"\
 /YX /Fo"$(INTDIR)/" /I\
 /cryptosoft/server/urlscreen" /I /cryptosoft/server/urlscreen" " " /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.\Debug/
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
BSC32_FLAGS=/nologo /o"$(OUTDIR)/proxy.bsc" 
BSC32_SBRS= \
	"$(INTDIR)\mod_proxy.sbr" \
	"$(INTDIR)\proxy_cache.sbr" \
	"$(INTDIR)\proxy_connect.sbr" \
	"$(INTDIR)\proxy_ftp.sbr" \
	"$(INTDIR)\proxy_http.sbr" \
	"$(INTDIR)\proxy_util.sbr"

"$(OUTDIR)\proxy.bsc" : "$(OUTDIR)" $(BSC32_SBRS)
    $(BSC32) @<<
  $(BSC32_FLAGS) $(BSC32_SBRS)
<<

LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo
LIB32_FLAGS=/nologo /out:"$(OUTDIR)/proxy.lib" 
LIB32_OBJS= \
	"$(INTDIR)\mod_proxy.obj" \
	"$(INTDIR)\proxy_cache.obj" \
	"$(INTDIR)\proxy_connect.obj" \
	"$(INTDIR)\proxy_ftp.obj" \
	"$(INTDIR)\proxy_http.obj" \
	"$(INTDIR)\proxy_util.obj"

"$(OUTDIR)\proxy.lib" : "$(OUTDIR)" $(DEF_FILE) $(LIB32_OBJS)
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

# Name "proxy - Win32 Release"
# Name "proxy - Win32 Debug"

!IF  "$(CFG)" == "proxy - Win32 Release"

!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

!ENDIF 

################################################################################
# Begin Source File

SOURCE=.\proxy_util.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_PROXY=\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\md5.h"\
	".\../..\multithread.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\proxy_util.obj" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_PROXY=\
	"..\..\conf.h"\
	".\../../regex\regex.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\md5.h"\
	".\../..\multithread.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\proxy_util.obj" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"

"$(INTDIR)\proxy_util.sbr" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_cache.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_PROXY_=\
	"..\..\nt\readdir.h"\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\md5.h"\
	".\../..\multithread.h"\
	".\../..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\UTIME.H"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_PROXY_=\
	"..\..\conf.h"\
	"..\..\nt\readdir.h"\
	".\../../regex\regex.h"\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\md5.h"\
	".\../..\multithread.h"\
	".\../..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	{$(INCLUDE)}"\sys\UTIME.H"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"

"$(INTDIR)\proxy_cache.sbr" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_connect.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_PROXY_C=\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\proxy_connect.obj" : $(SOURCE) $(DEP_CPP_PROXY_C) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_PROXY_C=\
	"..\..\conf.h"\
	".\../../regex\regex.h"\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\proxy_connect.obj" : $(SOURCE) $(DEP_CPP_PROXY_C) "$(INTDIR)"

"$(INTDIR)\proxy_connect.sbr" : $(SOURCE) $(DEP_CPP_PROXY_C) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_ftp.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_PROXY_F=\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_PROXY_F=\
	"..\..\conf.h"\
	".\../../regex\regex.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"

"$(INTDIR)\proxy_ftp.sbr" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\proxy_http.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_PROXY_H=\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\util_date.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_PROXY_H=\
	"..\..\conf.h"\
	".\../../regex\regex.h"\
	".\../..\http_log.h"\
	".\../..\http_main.h"\
	".\../..\httpd.h"\
	".\../..\util_date.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"

"$(INTDIR)\proxy_http.sbr" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"


!ENDIF 

# End Source File
################################################################################
# Begin Source File

SOURCE=.\mod_proxy.c

!IF  "$(CFG)" == "proxy - Win32 Release"

DEP_CPP_MOD_P=\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"


!ELSEIF  "$(CFG)" == "proxy - Win32 Debug"

DEP_CPP_MOD_P=\
	"..\..\conf.h"\
	".\../../regex\regex.h"\
	".\../..\httpd.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"\sys\STAT.H"\
	{$(INCLUDE)}"\sys\TYPES.H"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"

"$(INTDIR)\mod_proxy.sbr" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"


!ENDIF 

# End Source File
# End Target
# End Project
################################################################################
