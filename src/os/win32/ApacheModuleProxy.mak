# Microsoft Developer Studio Generated NMAKE File, Based on ApacheModuleProxy.dsp
!IF "$(CFG)" == ""
CFG=ApacheModuleProxy - Win32 Release
!MESSAGE No configuration specified. Defaulting to ApacheModuleProxy - Win32\
 Release.
!ENDIF 

!IF "$(CFG)" != "ApacheModuleProxy - Win32 Release" && "$(CFG)" !=\
 "ApacheModuleProxy - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ApacheModuleProxy.mak"\
 CFG="ApacheModuleProxy - Win32 Release"
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

CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ApacheModuleProxy - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(OUTDIR)\ApacheModuleProxy.dll"
	-@erase "$(OUTDIR)\ApacheModuleProxy.exp"
	-@erase "$(OUTDIR)\ApacheModuleProxy.lib"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MD /W3 /GX /O2 /I "..\..\main" /I "..\..\regex" /D "WIN32" /D\
 "NDEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\ApacheModuleProxy.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Release/
CPP_SBRS=.
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleProxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreR\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:no /pdb:"$(OUTDIR)\ApacheModuleProxy.pdb" /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleProxy.dll"\
 /implib:"$(OUTDIR)\ApacheModuleProxy.lib" 
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

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

!ELSE 

ALL : "$(OUTDIR)\ApacheModuleProxy.dll"

!ENDIF 

CLEAN :
	-@erase "$(INTDIR)\mod_proxy.obj"
	-@erase "$(INTDIR)\proxy_cache.obj"
	-@erase "$(INTDIR)\proxy_connect.obj"
	-@erase "$(INTDIR)\proxy_ftp.obj"
	-@erase "$(INTDIR)\proxy_http.obj"
	-@erase "$(INTDIR)\proxy_util.obj"
	-@erase "$(INTDIR)\vc50.idb"
	-@erase "$(INTDIR)\vc50.pdb"
	-@erase "$(OUTDIR)\ApacheModuleProxy.dll"
	-@erase "$(OUTDIR)\ApacheModuleProxy.exp"
	-@erase "$(OUTDIR)\ApacheModuleProxy.ilk"
	-@erase "$(OUTDIR)\ApacheModuleProxy.lib"
	-@erase "$(OUTDIR)\ApacheModuleProxy.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP_PROJ=/nologo /MDd /W3 /Gm /GX /Zi /Od /I "..\..\main" /I "..\..\regex" /D\
 "WIN32" /D "_DEBUG" /D "_WINDOWS" /Fp"$(INTDIR)\ApacheModuleProxy.pch" /YX\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 
CPP_OBJS=.\Debug/
CPP_SBRS=.
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\ApacheModuleProxy.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=..\..\CoreD\ApacheCore.lib kernel32.lib user32.lib gdi32.lib\
 winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib\
 uuid.lib odbc32.lib odbccp32.lib wsock32.lib /nologo /subsystem:windows /dll\
 /incremental:yes /pdb:"$(OUTDIR)\ApacheModuleProxy.pdb" /debug /machine:I386\
 /out:"$(OUTDIR)\ApacheModuleProxy.dll"\
 /implib:"$(OUTDIR)\ApacheModuleProxy.lib" 
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


!IF "$(CFG)" == "ApacheModuleProxy - Win32 Release" || "$(CFG)" ==\
 "ApacheModuleProxy - Win32 Debug"
SOURCE=.\mod_proxy.c
DEP_CPP_MOD_P=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_MOD_P=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\mod_proxy.obj" : $(SOURCE) $(DEP_CPP_MOD_P) "$(INTDIR)"


SOURCE=.\proxy_cache.c
DEP_CPP_PROXY=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_main.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\main\md5.h"\
	"..\..\main\multithread.h"\
	"..\..\main\util_date.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	{$(INCLUDE)}"sys\utime.h"\
	
NODEP_CPP_PROXY=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\proxy_cache.obj" : $(SOURCE) $(DEP_CPP_PROXY) "$(INTDIR)"


SOURCE=.\proxy_connect.c
DEP_CPP_PROXY_=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_main.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_PROXY_=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\proxy_connect.obj" : $(SOURCE) $(DEP_CPP_PROXY_) "$(INTDIR)"


SOURCE=.\proxy_ftp.c
DEP_CPP_PROXY_F=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_main.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	"..\standard\mod_mime.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_PROXY_F=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\proxy_ftp.obj" : $(SOURCE) $(DEP_CPP_PROXY_F) "$(INTDIR)"


SOURCE=.\proxy_http.c
DEP_CPP_PROXY_H=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_main.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\main\util_date.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_PROXY_H=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\proxy_http.obj" : $(SOURCE) $(DEP_CPP_PROXY_H) "$(INTDIR)"


SOURCE=.\proxy_util.c
DEP_CPP_PROXY_U=\
	"..\..\main\alloc.h"\
	"..\..\main\buff.h"\
	"..\..\main\conf.h"\
	"..\..\main\explain.h"\
	"..\..\main\http_config.h"\
	"..\..\main\http_log.h"\
	"..\..\main\http_main.h"\
	"..\..\main\http_protocol.h"\
	"..\..\main\httpd.h"\
	"..\..\main\md5.h"\
	"..\..\main\multithread.h"\
	"..\..\os\win32\readdir.h"\
	"..\..\regex\regex.h"\
	".\mod_proxy.h"\
	{$(INCLUDE)}"sys\stat.h"\
	{$(INCLUDE)}"sys\types.h"\
	
NODEP_CPP_PROXY_U=\
	"..\..\main\sfio.h"\
	

"$(INTDIR)\proxy_util.obj" : $(SOURCE) $(DEP_CPP_PROXY_U) "$(INTDIR)"



!ENDIF 

