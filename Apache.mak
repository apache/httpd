# Microsoft Developer Studio Generated NMAKE File, Based on Apache.dsp
!IF "$(CFG)" == ""
CFG=Apache - Win32 Release
!MESSAGE No configuration specified. Defaulting to Apache - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "Apache - Win32 Release" && "$(CFG)" != "Apache - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Apache.mak" CFG="Apache - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Apache - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "Apache - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "Apache - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "libhttpd - Win32 Release" "libaprutil - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\Apache.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN"\
 "libhttpd - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\Apache.idb"
	-@erase "$(INTDIR)\apache.res"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(OUTDIR)\Apache.exe"
	-@erase "$(OUTDIR)\Apache.map"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I "./include" /I "./os/win32" /I\
 "./srclib/apr/include" /I "./srclib/apr-util/include" /D "NDEBUG" /D "WIN32" /D\
 "_CONSOLE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Apache" /FD /c 
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

RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\apache.res" /d "NDEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib\
 /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Apache.pdb"\
 /map:"$(INTDIR)\Apache.map" /machine:I386 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\apache.res" \
	"$(INTDIR)\main.obj" \
	"$(OUTDIR)\libhttpd.lib" \
	".\srclib\apr-util\Release\libaprutil.lib" \
	".\srclib\apr\Release\libapr.lib"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\Apache.exe"

!ELSE 

ALL : "libhttpd - Win32 Debug" "libaprutil - Win32 Debug"\
 "libapr - Win32 Debug" "$(OUTDIR)\Apache.exe"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN"\
 "libhttpd - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\Apache.idb"
	-@erase "$(INTDIR)\apache.res"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(OUTDIR)\Apache.exe"
	-@erase "$(OUTDIR)\Apache.map"
	-@erase "$(OUTDIR)\Apache.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I "./include" /I "./os/win32" /I\
 "./srclib/apr/include" /I "./srclib/apr-util/include" /D "_DEBUG" /D "WIN32" /D\
 "_CONSOLE" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\Apache" /FD /c 
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

RSC=rc.exe
RSC_PROJ=/l 0x809 /fo"$(INTDIR)\apache.res" /d "_DEBUG" 
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\Apache.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib\
 /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\Apache.pdb"\
 /map:"$(INTDIR)\Apache.map" /debug /machine:I386 /out:"$(OUTDIR)\Apache.exe" 
LINK32_OBJS= \
	"$(INTDIR)\apache.res" \
	"$(INTDIR)\main.obj" \
	"$(OUTDIR)\libhttpd.lib" \
	".\srclib\apr-util\Debug\libaprutil.lib" \
	".\srclib\apr\Debug\libapr.lib"

"$(OUTDIR)\Apache.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "Apache - Win32 Release" || "$(CFG)" == "Apache - Win32 Debug"

!IF  "$(CFG)" == "Apache - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\.."

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

"libapr - Win32 Debug" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Debug" 
   cd "..\.."

"libapr - Win32 DebugCLEAN" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Debug"\
 RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "Apache - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\.."

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

"libaprutil - Win32 Debug" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Debug" 
   cd "..\.."

"libaprutil - Win32 DebugCLEAN" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Debug" RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "Apache - Win32 Release"

"libhttpd - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Release" 
   cd "."

"libhttpd - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak"\
 CFG="libhttpd - Win32 Release" RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"

"libhttpd - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug" 
   cd "."

"libhttpd - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libhttpd.mak" CFG="libhttpd - Win32 Debug"\
 RECURSE=1 
   cd "."

!ENDIF 

SOURCE=.\os\win32\apache.rc
DEP_RSC_APACH=\
	".\os\win32\apache.ico"\
	

!IF  "$(CFG)" == "Apache - Win32 Release"


"$(INTDIR)\apache.res" : $(SOURCE) $(DEP_RSC_APACH) "$(INTDIR)"
	$(RSC) /l 0x809 /fo"$(INTDIR)\apache.res" /i "os\win32" /d "NDEBUG" $(SOURCE)


!ELSEIF  "$(CFG)" == "Apache - Win32 Debug"


"$(INTDIR)\apache.res" : $(SOURCE) $(DEP_RSC_APACH) "$(INTDIR)"
	$(RSC) /l 0x809 /fo"$(INTDIR)\apache.res" /i "os\win32" /d "_DEBUG" $(SOURCE)


!ENDIF 

SOURCE=.\server\main.c
DEP_CPP_MAIN_=\
	".\include\ap_config.h"\
	".\include\ap_mmn.h"\
	".\include\ap_mpm.h"\
	".\include\ap_release.h"\
	".\include\http_config.h"\
	".\include\http_log.h"\
	".\include\http_main.h"\
	".\include\http_vhost.h"\
	".\include\httpd.h"\
	".\include\pcreposix.h"\
	".\include\util_cfgtree.h"\
	".\include\util_charset.h"\
	".\include\util_ebcdic.h"\
	".\os\win32\os.h"\
	".\srclib\apr-util\include\apr_hooks.h"\
	".\srclib\apr-util\include\apr_optional_hooks.h"\
	".\srclib\apr-util\include\apr_uri.h"\
	".\srclib\apr-util\include\apu.h"\
	".\srclib\apr\include\apr.h"\
	".\srclib\apr\include\apr_errno.h"\
	".\srclib\apr\include\apr_file_info.h"\
	".\srclib\apr\include\apr_file_io.h"\
	".\srclib\apr\include\apr_general.h"\
	".\srclib\apr\include\apr_getopt.h"\
	".\srclib\apr\include\apr_inherit.h"\
	".\srclib\apr\include\apr_lib.h"\
	".\srclib\apr\include\apr_network_io.h"\
	".\srclib\apr\include\apr_pools.h"\
	".\srclib\apr\include\apr_sms.h"\
	".\srclib\apr\include\apr_strings.h"\
	".\srclib\apr\include\apr_tables.h"\
	".\srclib\apr\include\apr_thread_proc.h"\
	".\srclib\apr\include\apr_time.h"\
	".\srclib\apr\include\apr_user.h"\
	".\srclib\apr\include\apr_want.h"\
	".\srclib\apr\include\apr_xlate.h"\
	
NODEP_CPP_MAIN_=\
	".\include\ap_config_auto.h"\
	".\server\xmlparse.h"\
	

"$(INTDIR)\main.obj" : $(SOURCE) $(DEP_CPP_MAIN_) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

