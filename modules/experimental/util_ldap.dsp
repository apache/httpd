# Microsoft Developer Studio Project File - Name="util_ldap" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** NICHT BEARBEITEN **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=util_ldap - Win32 Release
!MESSAGE Dies ist kein gültiges Makefile. Zum Erstellen dieses Projekts mit NMAKE
!MESSAGE verwenden Sie den Befehl "Makefile exportieren" und führen Sie den Befehl
!MESSAGE 
!MESSAGE NMAKE /f "util_ldap.mak".
!MESSAGE 
!MESSAGE Sie können beim Ausführen von NMAKE eine Konfiguration angeben
!MESSAGE durch Definieren des Makros CFG in der Befehlszeile. Zum Beispiel:
!MESSAGE 
!MESSAGE NMAKE /f "util_ldap.mak" CFG="util_ldap - Win32 Release"
!MESSAGE 
!MESSAGE Für die Konfiguration stehen zur Auswahl:
!MESSAGE 
!MESSAGE "util_ldap - Win32 Release" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE "util_ldap - Win32 Debug" (basierend auf  "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "util_ldap - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MD /W3 /O2 /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/ldap/include" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_AUTH_DBM_USE_APR" /Fd"Release\util_ldap" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /map /machine:I386 /out:"Release/util_ldap.so" /base:@..\..\os\win32\BaseAddr.ref,util_ldap
# ADD LINK32 kernel32.lib libhttpd.lib libapr.lib nsldap32v50.lib libaprutil.lib /nologo /subsystem:windows /dll /map /machine:I386 /out:"Release/util_ldap.so" /libpath:"..\..\release" /libpath:"..\..\srclib\apr\release" /libpath:"..\..\srclib\ldap\lib" /libpath:"..\..\srclib\apr-util\release" /libpath:"..\..\srclib\apr-util\Release" /base:@..\..\os\win32\BaseAddr.ref,util_ldap
# SUBTRACT LINK32 /debug

!ELSEIF  "$(CFG)" == "util_ldap - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Zi /Od /I "../../include" /I "../../srclib/apr/include" /I "../../srclib/apr-util/include" /I "../../srclib/ldap/include" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "AP_AUTH_DBM_USE_APR" /Fd"Debug\util_ldap" /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /out:"Debug/util_ldap.so" /base:@..\..\os\win32\BaseAddr.ref,util_ldap
# ADD LINK32 kernel32.lib libhttpd.lib libapr.lib nsldap32v50.lib libaprutil.lib /nologo /subsystem:windows /dll /incremental:no /map /debug /machine:I386 /out:"Debug/util_ldap.so" /libpath:"..\..\debug" /libpath:"..\..\srclib\apr\debug" /libpath:"..\..\srclib\ldap\lib" /libpath:"..\..\srclib\apr-util\debug" /libpath:"..\..\srclib\apr-util\Debug" /base:@..\..\os\win32\BaseAddr.ref,util_ldap

!ENDIF 

# Begin Target

# Name "util_ldap - Win32 Release"
# Name "util_ldap - Win32 Debug"
# Begin Source File

SOURCE=.\util_ldap.c

!IF  "$(CFG)" == "util_ldap - Win32 Release"

# ADD CPP /D "LDAP_DECLARE_EXPORT"

!ELSEIF  "$(CFG)" == "util_ldap - Win32 Debug"

# ADD CPP /D "LDAP_DECLARE_EXPORT"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\util_ldap.rc
# End Source File
# Begin Source File

SOURCE=.\util_ldap_cache.c
# End Source File
# Begin Source File

SOURCE=.\util_ldap_cache_mgr.c
# End Source File
# Begin Source File

SOURCE=..\..\build\win32\win32ver.awk

!IF  "$(CFG)" == "util_ldap - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\util_ldap.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk util_ldap  "auth_dbm_module for Apache" ../../include/ap_release.h > .\util_ldap.rc

# End Custom Build

!ELSEIF  "$(CFG)" == "util_ldap - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Creating Version Resource
InputPath=..\..\build\win32\win32ver.awk

".\util_ldap.rc" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	awk -f ../../build/win32/win32ver.awk util_ldap  "auth_dbm_module for Apache" ../../include/ap_release.h > .\util_ldap.rc

# End Custom Build

!ENDIF 

# End Source File
# End Target
# End Project
