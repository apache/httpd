'

' To permit this cgi, replace ' on the first line above with the
' appropriate shebang, f.e. '!c:/windows/system32/cscript -nologo
'
' ***** !!! WARNING !!! *****
' This script echoes the server environment variables and therefore
' leaks information - so NEVER use it in a live server environment!
' It is provided only for testing purpose.
' Also note that it is subject to cross site scripting attacks on
' MS IE and any other browser which fails to honor RFC2616. 

''
''  printenv -- demo CGI program which just prints its environment
''
Option Explicit

Dim objShell, objArray, str, envvar, envval
Set objShell = CreateObject("WScript.Shell")
Set objArray = CreateObject("System.Collections.ArrayList")

WScript.StdOut.WriteLine "Content-type: text/plain; charset=iso-8859-1" & vbLF
For Each str In objShell.Environment("PROCESS")
  objArray.Add str
Next
objArray.Sort()
For Each str In objArray
  envvar = Left(str, InStr(str, "="))
  envval = Replace(Mid(str, InStr(str, "=") + 1), vbLF, "\n")
  WScript.StdOut.WriteLine envvar & Chr(34) & envval & Chr(34)
Next

