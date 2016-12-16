# Microsoft Developer Studio Project File - Name="BuildAll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=BuildAll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "BuildAll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "BuildAll.mak" CFG="BuildAll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "BuildAll - Win32 Release" (based on "Win32 (x86) External Target")
!MESSAGE "BuildAll - Win32 Debug" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "BuildAll - Win32 Release"

# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "NMAKE /f makefile.win"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache2\bin\httpd.exe"
# PROP BASE Bsc_Name ".\Browse\BuildAll.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache2" LONG=Release _dummy"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache2\bin\httpd.exe"
# PROP Bsc_Name ".\Browse\httpd.bsc"
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "BuildAll - Win32 Debug"

# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "NMAKE /f makefile.win"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache2\bin\httpd.exe"
# PROP BASE Bsc_Name ".\Browse\BuildAll.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache2" LONG=Debug _dummy"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache2\bin\httpd.exe"
# PROP Bsc_Name ".\Browse\httpd.bsc"
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "BuildAll - Win32 Release"
# Name "BuildAll - Win32 Debug"

!IF  "$(CFG)" == "BuildAll - Win32 Release"

!ELSEIF  "$(CFG)" == "BuildAll - Win32 Debug"

!ENDIF 

# Begin Source File

SOURCE=.\os\win32\BaseAddr.ref
# End Source File
# Begin Source File

SOURCE=.\CHANGES
# End Source File
# Begin Source File

SOURCE=.\Makefile.win
# End Source File
# Begin Source File

SOURCE=.\STATUS
# End Source File
# End Target
# End Project
