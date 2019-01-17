# Microsoft Developer Studio Project File - Name="InstallBin" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=InstallBin - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "InstallBin.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "InstallBin.mak" CFG="InstallBin - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "InstallBin - Win32 Release" (based on "Win32 (x86) External Target")
!MESSAGE "InstallBin - Win32 Debug" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "InstallBin - Win32 Release"

# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Cmd_Line "NMAKE /f InstallBin.mak"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache24\bin\httpd.exe"
# PROP BASE Bsc_Name "InstallBin.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache24" SHORT=R LONG=Release _install"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache24\bin\httpd.exe"
# PROP Bsc_Name "Browse\httpd.bsc"
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "InstallBin - Win32 Debug"

# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Cmd_Line "NMAKE /f InstallBin.mak"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache24\bin\httpd.exe"
# PROP BASE Bsc_Name "InstallBin.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache24" SHORT=D LONG=Debug _install"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache24\bin\httpd.exe"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "InstallBin - Win32 Release"
# Name "InstallBin - Win32 Debug"

!IF  "$(CFG)" == "InstallBin - Win32 Release"

!ELSEIF  "$(CFG)" == "InstallBin - Win32 Debug"

!ENDIF 

# Begin Source File

SOURCE=..\logs\access.log
# End Source File
# Begin Source File

SOURCE=.\os\win32\BaseAddr.ref
# End Source File
# Begin Source File

SOURCE=.\CHANGES
# End Source File
# Begin Source File

SOURCE=..\logs\error.log
# End Source File
# Begin Source File

SOURCE=..\conf\httpd.conf
# End Source File
# Begin Source File

SOURCE=.\Makefile.win
# End Source File
# Begin Source File

SOURCE=..\STATUS
# End Source File
# End Target
# End Project
