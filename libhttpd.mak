# Microsoft Developer Studio Generated NMAKE File, Based on libhttpd.dsp
!IF "$(CFG)" == ""
CFG=libhttpd - Win32 Release
!MESSAGE No configuration specified. Defaulting to libhttpd - Win32 Release.
!ENDIF 

!IF "$(CFG)" != "libhttpd - Win32 Release" && "$(CFG)" !=\
 "libhttpd - Win32 Debug"
!MESSAGE Invalid configuration "$(CFG)" specified.
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libhttpd.mak" CFG="libhttpd - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libhttpd - Win32 Release" (based on\
 "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libhttpd - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 
!ERROR An invalid configuration is specified.
!ENDIF 

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

!IF  "$(CFG)" == "libhttpd - Win32 Release"

OUTDIR=.\Release
INTDIR=.\Release
# Begin Custom Macros
OutDir=.\Release
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\libhttpd.dll"

!ELSE 

ALL : "libaprutil - Win32 Release" "libexpat - Win32 Release"\
 "httpd - Win32 Release" "pcreposix - Win32 Release" "pcre - Win32 Release"\
 "libapr - Win32 Release" "$(OUTDIR)\libhttpd.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 ReleaseCLEAN" "pcre - Win32 ReleaseCLEAN"\
 "pcreposix - Win32 ReleaseCLEAN" "httpd - Win32 ReleaseCLEAN"\
 "libexpat - Win32 ReleaseCLEAN" "libaprutil - Win32 ReleaseCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\libhttpd.obj"
	-@erase "$(OUTDIR)\libhttpd.dll"
	-@erase "$(OUTDIR)\libhttpd.exp"
	-@erase "$(OUTDIR)\libhttpd.lib"
	-@erase "$(OUTDIR)\libhttpd.map"
	-@erase ".\Debug\libhttpd.idb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /I ".\include" /I ".\lib\apr\include" /I\
 ".\os\win32" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT"\
 /Fo"$(INTDIR)\\" /Fd"Debug\libhttpd" /FD /c 
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
MTL_PROJ=/nologo /D "NDEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libhttpd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib\
 /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\libhttpd.pdb"\
 /map:"$(INTDIR)\libhttpd.map" /machine:I386 /def:".\libhttpd.def"\
 /out:"$(OUTDIR)\libhttpd.dll" /implib:"$(OUTDIR)\libhttpd.lib"\
 /base:@"os\win32\BaseAddr.ref",libhttpd 
DEF_FILE= \
	".\libhttpd.def"
LINK32_OBJS= \
	"$(INTDIR)\libhttpd.obj" \
	".\LibR\httpd.lib" \
	".\srclib\apr-util\Release\libaprutil.lib" \
	".\srclib\apr\Release\libapr.lib" \
	".\srclib\expat-lite\Release\libexpat.lib" \
	".\srclib\pcre\LibR\pcre.lib" \
	".\srclib\pcre\LibR\pcreposix.lib"

"$(OUTDIR)\libhttpd.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

OUTDIR=.\Debug
INTDIR=.\Debug
# Begin Custom Macros
OutDir=.\Debug
# End Custom Macros

!IF "$(RECURSE)" == "0" 

ALL : "$(OUTDIR)\libhttpd.dll"

!ELSE 

ALL : "libaprutil - Win32 Debug" "libexpat - Win32 Debug" "httpd - Win32 Debug"\
 "pcreposix - Win32 Debug" "pcre - Win32 Debug" "libapr - Win32 Debug"\
 "$(OUTDIR)\libhttpd.dll"

!ENDIF 

!IF "$(RECURSE)" == "1" 
CLEAN :"libapr - Win32 DebugCLEAN" "pcre - Win32 DebugCLEAN"\
 "pcreposix - Win32 DebugCLEAN" "httpd - Win32 DebugCLEAN"\
 "libexpat - Win32 DebugCLEAN" "libaprutil - Win32 DebugCLEAN" 
!ELSE 
CLEAN :
!ENDIF 
	-@erase "$(INTDIR)\libhttpd.idb"
	-@erase "$(INTDIR)\libhttpd.obj"
	-@erase "$(OUTDIR)\libhttpd.dll"
	-@erase "$(OUTDIR)\libhttpd.exp"
	-@erase "$(OUTDIR)\libhttpd.lib"
	-@erase "$(OUTDIR)\libhttpd.map"
	-@erase "$(OUTDIR)\libhttpd.pdb"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MDd /W3 /GX /Zi /Od /I ".\include" /I ".\lib\apr\include" /I\
 ".\os\win32" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_DECLARE_EXPORT"\
 /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\libhttpd" /FD /c 
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
MTL_PROJ=/nologo /D "_DEBUG" /mktyplib203 /win32 
RSC=rc.exe
BSC32=bscmake.exe
BSC32_FLAGS=/nologo /o"$(OUTDIR)\libhttpd.bsc" 
BSC32_SBRS= \
	
LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib advapi32.lib ws2_32.lib mswsock.lib\
 /nologo /subsystem:windows /dll /incremental:no /pdb:"$(OUTDIR)\libhttpd.pdb"\
 /map:"$(INTDIR)\libhttpd.map" /debug /machine:I386 /def:".\libhttpd.def"\
 /out:"$(OUTDIR)\libhttpd.dll" /implib:"$(OUTDIR)\libhttpd.lib"\
 /base:@"os\win32\BaseAddr.ref",libhttpd 
DEF_FILE= \
	".\libhttpd.def"
LINK32_OBJS= \
	"$(INTDIR)\libhttpd.obj" \
	".\LibD\httpd.lib" \
	".\srclib\apr-util\Debug\libaprutil.lib" \
	".\srclib\apr\Debug\libapr.lib" \
	".\srclib\expat-lite\Debug\libexpat.lib" \
	".\srclib\pcre\LibD\pcre.lib" \
	".\srclib\pcre\LibD\pcreposix.lib"

"$(OUTDIR)\libhttpd.dll" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<

!ENDIF 


!IF "$(CFG)" == "libhttpd - Win32 Release" || "$(CFG)" ==\
 "libhttpd - Win32 Debug"

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"libapr - Win32 Release" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) /F ".\libapr.mak" CFG="libapr - Win32 Release" 
   cd "..\.."

"libapr - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libapr.mak" CFG="libapr - Win32 Release"\
 RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

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

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"pcre - Win32 Release" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Release" 
   cd "..\.."

"pcre - Win32 ReleaseCLEAN" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Release"\
 RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

"pcre - Win32 Debug" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcre.mak" CFG="pcre - Win32 Debug" 
   cd "..\.."

"pcre - Win32 DebugCLEAN" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcre.mak" CFG="pcre - Win32 Debug"\
 RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"pcreposix - Win32 Release" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcreposix.mak" CFG="pcreposix - Win32 Release" 
   cd "..\.."

"pcreposix - Win32 ReleaseCLEAN" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcreposix.mak"\
 CFG="pcreposix - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

"pcreposix - Win32 Debug" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) /F ".\pcreposix.mak" CFG="pcreposix - Win32 Debug" 
   cd "..\.."

"pcreposix - Win32 DebugCLEAN" : 
   cd ".\srclib\pcre"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\pcreposix.mak"\
 CFG="pcreposix - Win32 Debug" RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"httpd - Win32 Release" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\httpd.mak" CFG="httpd - Win32 Release" 
   cd "."

"httpd - Win32 ReleaseCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\httpd.mak" CFG="httpd - Win32 Release"\
 RECURSE=1 
   cd "."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

"httpd - Win32 Debug" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) /F ".\httpd.mak" CFG="httpd - Win32 Debug" 
   cd "."

"httpd - Win32 DebugCLEAN" : 
   cd "."
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\httpd.mak" CFG="httpd - Win32 Debug"\
 RECURSE=1 
   cd "."

!ENDIF 

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"libexpat - Win32 Release" : 
   cd ".\srclib\expat-lite"
   $(MAKE) /$(MAKEFLAGS) /F ".\libexpat.mak" CFG="libexpat - Win32 Release" 
   cd "..\.."

"libexpat - Win32 ReleaseCLEAN" : 
   cd ".\srclib\expat-lite"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libexpat.mak"\
 CFG="libexpat - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

"libexpat - Win32 Debug" : 
   cd ".\srclib\expat-lite"
   $(MAKE) /$(MAKEFLAGS) /F ".\libexpat.mak" CFG="libexpat - Win32 Debug" 
   cd "..\.."

"libexpat - Win32 DebugCLEAN" : 
   cd ".\srclib\expat-lite"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libexpat.mak" CFG="libexpat - Win32 Debug"\
 RECURSE=1 
   cd "..\.."

!ENDIF 

!IF  "$(CFG)" == "libhttpd - Win32 Release"

"libaprutil - Win32 Release" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) /F ".\libaprutil.mak" CFG="libaprutil - Win32 Release"\
 
   cd "..\.."

"libaprutil - Win32 ReleaseCLEAN" : 
   cd ".\srclib\apr-util"
   $(MAKE) /$(MAKEFLAGS) CLEAN /F ".\libaprutil.mak"\
 CFG="libaprutil - Win32 Release" RECURSE=1 
   cd "..\.."

!ELSEIF  "$(CFG)" == "libhttpd - Win32 Debug"

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

SOURCE=.\os\win32\libhttpd.c

"$(INTDIR)\libhttpd.obj" : $(SOURCE) "$(INTDIR)"
	$(CPP) $(CPP_PROJ) $(SOURCE)



!ENDIF 

