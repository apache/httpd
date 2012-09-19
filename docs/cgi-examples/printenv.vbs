'!c:/windows/system32/cscript -nologo
'#
'#  printenv -- demo CGI program which just prints its environment
'#
Option Explicit

Dim objShell, objArray, str, env
Set objShell = CreateObject("WScript.Shell")
Set objArray = CreateObject("System.Collections.ArrayList")

Wscript.Echo "Content-type: text/plain; charset=iso-8859-1" & vbLF
For Each str In objShell.Environment("PROCESS")
  env = Split(str, "=", 2)
  env(1) = Replace(env(1), vbLF, "\n")
  objArray.Add env(0) & "=" & Chr(34) & env(1) & Chr(34)
Next
objArray.Sort()
For Each str In objArray
  WScript.Echo str
Next

'WScript.Echo ScriptEngine & " Version=" & ScriptEngineMajorVersion & "." & _
'             ScriptEngineMinorVersion & "." & ScriptEngineBuildVersion

