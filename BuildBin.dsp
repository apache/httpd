# Microsoft Developer Studio Project File - Name="BuildBin" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=BuildBin - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "BuildBin.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "BuildBin.mak" CFG="BuildBin - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "BuildBin - Win32 Release" (based on "Win32 (x86) External Target")
!MESSAGE "BuildBin - Win32 Debug" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "BuildBin - Win32 Release"

# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "NMAKE /f makefile.win"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache2\bin\httpd.exe"
# PROP BASE Bsc_Name ".\Browse\BuildBin.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 0
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache2" LONG=Release _trydb _trylua _tryssl _tryzlib _tryserf _dummy"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache2\bin\httpd.exe"
# PROP Bsc_Name ".\Browse\httpd.bsc"
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "BuildBin - Win32 Debug"

# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir ""
# PROP BASE Intermediate_Dir ""
# PROP BASE Cmd_Line "NMAKE /f makefile.win"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "\Apache2\bin\httpd.exe"
# PROP BASE Bsc_Name ".\Browse\BuildBin.bsc"
# PROP BASE Target_Dir ""
# PROP Use_Debug_Libraries 1
# PROP Output_Dir ""
# PROP Intermediate_Dir ""
# PROP Cmd_Line "NMAKE /f makefile.win INSTDIR="\Apache2" LONG=Debug _trydb _trylua _tryssl _tryzlib _tryserf _dummy"
# PROP Rebuild_Opt ""
# PROP Target_File "\Apache2\bin\httpd.exe"
# PROP Bsc_Name ".\Browse\httpd.bsc"
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "BuildBin - Win32 Release"
# Name "BuildBin - Win32 Debug"

!IF  "$(CFG)" == "BuildBin - Win32 Release"

!ELSEIF  "$(CFG)" == "BuildBin - Win32 Debug"

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
