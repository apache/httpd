/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 */

/* --------------------------------------------------------------------
 *
 * wintty : a Apache/WinNT support utility for monitoring and 
 *          reflecting user feedback from the Apache process via
 *          stdin/stdout, even as running within the service context.
 *
 * Originally contributed by William Rowe <wrowe@covalent.net>
 *
 * Note: this implementation is _very_ experimental, and error handling
 * is far from complete.  Using it as a cgi or pipe process allows the
 * programmer to discover if facilities such as reliable piped logs
 * are working as expected, or answer operator prompts that would
 * otherwise be discarded by the service process.
 *
 * Also note the isservice detection semantics, which far exceed any
 * mechanism we have discovered thus far.
 * 
 * --------------------------------------------------------------------
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

const char *options = 
"\nwintty: a utility for echoing the stdin stream to a new console window,\n"
"\teven when invoked from within a service (such as the Apache server.)\n"
"\tAlso reflects the console input back to the stdout stream, allowing\n"
"\tthe operator to respond to prompts from the context of a service.\n\n"
"Syntax: %s [opts] [-t \"Window Title\"]\n\n"
"  opts: -c{haracter}   or -l{ine} input\n"
"\t-q{uiet}       or -e{cho} input\n"
"\t-u{nprocessed} or -p{rocessed} input\n"
"\t-n{owrap}      or -w{rap} output lines\n"
"\t-f{ormatted}   or -r{aw} output lines\n"
"\t-v{erbose} error reporting (for debugging)\n"
"\t-? for this message\n\n";

HANDLE herrout;
BOOL verbose = FALSE;

void printerr(char *fmt, ...) 
{
    char str[1024];
    va_list args;
    DWORD len;
    if (!verbose)
        return;
    va_start(args, fmt);
    wvsprintf(str, fmt, args);
    WriteFile(herrout, str, len = strlen(str), &len, NULL);
}

DWORD WINAPI feedback(LPVOID pipeout);

int main(int argc, char** argv)
{
    char str[1024], *contitle;
    HANDLE hproc, thread;
    HANDLE hwinsta, hsavewinsta;
    HANDLE hdesk, hsavedesk;
    HANDLE conin, conout;
    HANDLE pipein, pipeout;
    HANDLE hstdin, hstdout, hstderr;
    DWORD conmode;
    DWORD newinmode = 0, notinmode = 0;
    DWORD newoutmode = 0, notoutmode = 0;
    DWORD tid;
    DWORD len;
    BOOL isservice = FALSE;
    char *arg0 = argv[0];

    while (--argc) {
        ++argv;
        if (**argv == '/' || **argv == '-') {
            switch (tolower((*argv)[1])) {
                case 'c':
                    notinmode |= ENABLE_LINE_INPUT;          break;
                case 'l':
                    newinmode |= ENABLE_LINE_INPUT;          break;
                case 'q':
                    notinmode |= ENABLE_ECHO_INPUT;          break;
                case 'e':
                    newinmode |= ENABLE_ECHO_INPUT;          break;
                case 'u':
                    notinmode |= ENABLE_PROCESSED_INPUT;     break;
                case 'p':
                    newinmode |= ENABLE_PROCESSED_INPUT;     break;
                case 'n':
                    notoutmode |= ENABLE_WRAP_AT_EOL_OUTPUT; break;
                case 'w':
                    newoutmode |= ENABLE_WRAP_AT_EOL_OUTPUT; break;
                case 'r':
                    notoutmode |= ENABLE_PROCESSED_OUTPUT;   break;
                case 'f':
                    newoutmode |= ENABLE_PROCESSED_OUTPUT;   break;
                case 'v':
                    verbose = TRUE;
                    break;
                case 't':
                    contitle = *(++argv);
                    --argc;
                    break;
                case '?':
                    printf(options, arg0);
                    exit(1);
		default:
                    printf("wintty option %s not recognized, use -? for help.\n\n", *argv);
                    exit(1);
            }
        }
        else {
            printf("wintty argument %s not understood, use -? for help.\n\n", *argv);
            exit(1);
        }
    }

    hproc = GetCurrentProcess();
    herrout = hstderr = GetStdHandle(STD_ERROR_HANDLE);
    if (!hstderr || hstderr == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_ERROR_HANDLE) failed (%d)\n", GetLastError());
    }
    else if (!DuplicateHandle(hproc, hstderr,
                         hproc, &herrout, 0, FALSE, 
                         DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
        printerr("DupHandle(stderr) failed (%d)\n", GetLastError());
    }

    hstdin = GetStdHandle(STD_INPUT_HANDLE);
    if (!hstdin || hstdin == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_INPUT_HANDLE) failed (%d)\n", GetLastError());
    }
    else if (!DuplicateHandle(hproc, hstdin,
                         hproc, &pipein, 0, FALSE, 
                         DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
        printerr("DupHandle(stdin) failed (%d)\n", GetLastError());
    }

    hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hstdout || hstdout == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_OUTPUT_HANDLE) failed (%d)\n", GetLastError());
    }
    else if (!DuplicateHandle(hproc, hstdout,
                         hproc, &pipeout, 0, FALSE, 
                         DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
        printerr("DupHandle(stdout) failed (%d)\n", GetLastError());
    }

    hsavewinsta = GetProcessWindowStation();
    if (!hsavewinsta || hsavewinsta == INVALID_HANDLE_VALUE) {
        printerr("GetProcWinSta() failed (%d)\n", GetLastError());
    }
    else if (!GetUserObjectInformation(hsavewinsta, UOI_NAME, str, sizeof(str), &len)) {
        printerr("GetUserObjectInfo(GetProcWinSta) failed (%d)\n", GetLastError());
        CloseHandle(hsavewinsta);
    }
    else if (strnicmp(str, "Service-", 8) == 0) {
        isservice = TRUE;
    }
    else
        CloseHandle(hsavewinsta);
    SetLastError(0);

    if (!FreeConsole())
        printerr("DupHandle(stdout) failed (%d)\n", GetLastError());

    if (isservice) {
        hwinsta = OpenWindowStation("WinSta0", TRUE, 
                            WINSTA_ACCESSCLIPBOARD     
                          | WINSTA_ACCESSGLOBALATOMS  
                          | WINSTA_ENUMDESKTOPS
                          | WINSTA_ENUMERATE     
                          | WINSTA_READATTRIBUTES  
                          | WINSTA_READSCREEN
                          | WINSTA_WRITEATTRIBUTES);
        if (!hwinsta || hwinsta == INVALID_HANDLE_VALUE) {
            printerr("OpenWinSta(WinSta0) failed (%d)\n", GetLastError());
        }
        else if (!SetProcessWindowStation(hwinsta)) {
            printerr("SetProcWinSta(WinSta0) failed (%d)\n", GetLastError());
        }
	hsavedesk = GetThreadDesktop(GetCurrentThreadId());
        if (!hsavedesk || hsavedesk == INVALID_HANDLE_VALUE) {
            printerr("GetThreadDesktop(GetTID()) failed (%d)\n", GetLastError());
        }
        hdesk = OpenDesktop("Default", 0, TRUE, 
                            DESKTOP_READOBJECTS     
                          | DESKTOP_CREATEWINDOW    
                          | DESKTOP_CREATEMENU      
                          | DESKTOP_HOOKCONTROL     
                          | DESKTOP_JOURNALRECORD   
                          | DESKTOP_JOURNALPLAYBACK 
                          | DESKTOP_ENUMERATE       
                          | DESKTOP_WRITEOBJECTS);
        if (!hdesk || hdesk == INVALID_HANDLE_VALUE) {
            printerr("OpenDesktop(Default) failed (%d)\n", GetLastError());
        } 
        else if (!SetThreadDesktop(hdesk)) {
            printerr("SetThreadDesktop(Default) failed (%d)\n", GetLastError());
        }
    }

    if (!AllocConsole()) {
        printerr("AllocConsole(Default) failed (%d)\n", GetLastError());
    }

    if (contitle && !SetConsoleTitle(contitle)) {
        printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
    }

    conout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!conout || conout == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_OUTPUT_HANDLE) failed (%d)\n", GetLastError());
    }
    else if (!GetConsoleMode(conout, &conmode)) {
        printerr("GetConsoleMode(CONOUT) failed (%d)\n", GetLastError());
    }
    else if (!SetConsoleMode(conout, conmode = ((conmode | newoutmode) & ~notoutmode))) {
        printerr("SetConsoleMode(CONOUT, 0x%x) failed (%d)\n", conmode, GetLastError());
    }

    conin = GetStdHandle(STD_INPUT_HANDLE);
    if (!conin || conin == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_INPUT_HANDLE) failed (%d)\n", GetLastError());
    }
    else if (!GetConsoleMode(conin, &conmode)) {
        printerr("GetConsoleMode(CONOUT) failed (%d)\n", GetLastError());
    }
    else if (!SetConsoleMode(conin, conmode = ((conmode | newinmode) & ~notinmode))) {
        printerr("SetConsoleMode(CONIN, 0x%x) failed (%d)\n", conmode, GetLastError());
    }

    thread = CreateThread(NULL, 0, feedback, (LPVOID)pipeout, 0, &tid);

    while (ReadFile(pipein, str, sizeof(str), &len, NULL))
        if (!len || !WriteFile(conout, str, len, &len, NULL))
           break;

    printerr("[EOF] from stdin (%d)\n", GetLastError());

    CloseHandle(pipeout);
    if (!GetConsoleTitle(str, sizeof(str))) {
        printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
    }
    else {
        strcat(str, " - [Finished]");
        if (!SetConsoleTitle(str)) {
            printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
        }
    }

    WaitForSingleObject(thread, INFINITE);
    FreeConsole();
    CloseHandle(herrout);
    if (isservice) {
        if (!SetProcessWindowStation(hsavewinsta)) {
            len = GetLastError();
        }
        if (!SetThreadDesktop(hsavedesk)) {
            len = GetLastError();
        }
        CloseDesktop(hdesk);
        CloseWindowStation(hwinsta);
    }
    return 0;
}


DWORD WINAPI feedback(LPVOID arg)
{
    HANDLE conin;
    HANDLE pipeout = (HANDLE)arg;
    char *str[1024];
    DWORD len;

    conin = GetStdHandle(STD_INPUT_HANDLE);
    if (!conin) {
        len = GetLastError();
    }

    while (ReadFile(conin, str, sizeof(str), &len, NULL))
        if (!len || !WriteFile(pipeout, str, len, &len, NULL))
            break;

    printerr("[EOF] from Console (%d)\n", GetLastError());

    return 0;
}
