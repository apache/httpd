/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2003 The Apache Software Foundation.  All rights
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
"\t-O{output} [number of seconds]\n"
"\t-v{erbose} error reporting (for debugging)\n"
"\t-? for this message\n\n";

BOOL verbose = FALSE;

void printerr(char *fmt, ...) 
{
    char str[1024];
    va_list args;
    if (!verbose)
        return;
    va_start(args, fmt);
    wvsprintf(str, fmt, args);
    OutputDebugString(str);
}

DWORD WINAPI feedback(LPVOID args);

typedef struct feedback_args_t {
    HANDLE in;
    HANDLE out;
} feedback_args_t;

int main(int argc, char** argv)
{
    char str[1024], *contitle = NULL;
    HANDLE hproc, thread;
    HANDLE hwinsta = NULL, hsavewinsta;
    HANDLE hdesk = NULL, hsavedesk = NULL;
    HANDLE conin, conout;
    HANDLE hstdin, hstdout, hstderr, hdup;
    feedback_args_t feed;
    DWORD conmode;
    DWORD newinmode = 0, notinmode = 0;
    DWORD newoutmode = 0, notoutmode = 0;
    DWORD tid;
    DWORD len;
    DWORD timeout = INFINITE;
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
                case 'o':
                    if (*(argv + 1) && *(argv + 1)[0] != '-') {
                        *(++argv);
                        timeout = atoi(*argv) / 1000;
                        --argc;
                    }
                    else {
                        timeout = 0;
                    }	
                    break;
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
    hsavewinsta = GetProcessWindowStation();
    if (!hsavewinsta || hsavewinsta == INVALID_HANDLE_VALUE) {
        printerr("GetProcessWindowStation() failed (%d)\n", GetLastError());
    }
    else if (!GetUserObjectInformation(hsavewinsta, UOI_NAME, str, sizeof(str), &len)) {
        printerr("GetUserObjectInfoformation(hWinSta) failed (%d)\n", GetLastError());
    }
    else if (strnicmp(str, "Service-", 8) == 0) {
        printerr("WindowStation Name %s is a service\n", str);
        isservice = TRUE;
    }
    SetLastError(0);

    hstdin = GetStdHandle(STD_INPUT_HANDLE);
    if (!hstdin || hstdin == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_INPUT_HANDLE) failed (%d)\n", 
                 GetLastError());
    }
    else if (DuplicateHandle(hproc, hstdin, hproc, &hdup, 0, 
                             isservice, DUPLICATE_SAME_ACCESS)) {
        CloseHandle(hstdin);
        hstdin = hdup;
    }
    else {
        printerr("DupHandle(stdin [%x]) failed (%d)\n", 
                 hstdin, GetLastError());
    }

    hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!hstdout || hstdout == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_OUTPUT_HANDLE) failed (%d)\n", 
                 GetLastError());
    }
    else if (DuplicateHandle(hproc, hstdout, hproc, &hdup, 0, 
                             isservice, DUPLICATE_SAME_ACCESS)) {
        CloseHandle(hstdout);
        hstdout = hdup;
    }
    else {
        printerr("DupHandle(stdout [%x]) failed (%d)\n", 
                 hstdout, GetLastError());
    }

    hstderr = GetStdHandle(STD_ERROR_HANDLE);
    if (!hstderr || hstderr == INVALID_HANDLE_VALUE) {
        printerr("GetStdHandle(STD_ERROR_HANDLE) failed (%d)\n", 
                 GetLastError());
    }
    else if (DuplicateHandle(hproc, hstderr, hproc, &hdup, 0, 
                             isservice, DUPLICATE_SAME_ACCESS)) {
        CloseHandle(hstderr);
        hstderr = hdup;
    }
    else {
        printerr("DupHandle(stderr [%x]) failed (%d)\n", 
                 hstderr, GetLastError());
    }

    /* You can't close the console till all the handles above were
     * rescued by DuplicateHandle()
     */
    if (!FreeConsole())
        printerr("FreeConsole() failed (%d)\n", GetLastError());
        
    if (isservice) {
#ifdef WE_EVER_FIGURE_OUT_WHY_THIS_DOESNT_WORK
	hsavedesk = GetThreadDesktop(GetCurrentThreadId());
        if (!hsavedesk || hsavedesk == INVALID_HANDLE_VALUE) {
            printerr("GetThreadDesktop(GetTID()) failed (%d)\n", GetLastError());
        }
        CloseWindowStation(hwinsta);
        hwinsta = OpenWindowStation("WinSta0", TRUE, MAXIMUM_ALLOWED);
        if (!hwinsta || hwinsta == INVALID_HANDLE_VALUE) {
            printerr("OpenWinSta(WinSta0) failed (%d)\n", GetLastError());
        }
        else if (!SetProcessWindowStation(hwinsta)) {
            printerr("SetProcWinSta(WinSta0) failed (%d)\n", GetLastError());
        }
        hdesk = OpenDesktop("Default", 0, TRUE, MAXIMUM_ALLOWED);
        if (!hdesk || hdesk == INVALID_HANDLE_VALUE) {
            printerr("OpenDesktop(Default) failed (%d)\n", GetLastError());
        } 
        else if (!SetThreadDesktop(hdesk)) {
            printerr("SetThreadDesktop(Default) failed (%d)\n", GetLastError());
        }
#else
        PROCESS_INFORMATION pi;
        STARTUPINFO si;
        DWORD exitcode = 1;
        char appbuff[MAX_PATH];
        char *appname = NULL;
        char *cmdline = GetCommandLine();
        
        if (!GetModuleFileName(NULL, appbuff, sizeof(appbuff))) {
            appname = appbuff;
        }
        
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags     = STARTF_USESHOWWINDOW
                       | STARTF_USESTDHANDLES;
        si.lpDesktop   = "WinSta0\\Default";
        si.wShowWindow = 1;  /* SW_SHOWNORMAL */
        si.hStdInput   = hstdin;
        si.hStdOutput  = hstdout;
        si.hStdError   = hstderr;

        /* Instantly, upon creating the new process, we will close our
         * copies of the handles so our parent isn't confused when the
         * child closes their copy of the handle.  Without this action,
         * we would hold a copy of the handle, and the parent would not
         * receive their EOF notification.
         */
        if (CreateProcess(appname, cmdline, NULL, NULL, TRUE,
                          CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
                          NULL, NULL, &si, &pi)) {
            CloseHandle(si.hStdInput);
            CloseHandle(si.hStdOutput);
            CloseHandle(si.hStdError);
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            WaitForSingleObject(pi.hProcess, INFINITE);
            GetExitCodeProcess(pi.hProcess, &exitcode);
            CloseHandle(pi.hProcess);
            return exitcode;
        }
        return 1;
#endif
    }

    if (!AllocConsole()) {
        printerr("AllocConsole(Default) failed (%d)\n", GetLastError());
    }

    if (contitle && !SetConsoleTitle(contitle)) {
        printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
    }

    conout = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, 
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 
                        FALSE, OPEN_EXISTING, 0, NULL);
    if (!conout || conout == INVALID_HANDLE_VALUE) {
        printerr("CreateFile(CONOUT$) failed (%d)\n", GetLastError());
    }
    else if (!GetConsoleMode(conout, &conmode)) {
        printerr("GetConsoleMode(CONOUT) failed (%d)\n", GetLastError());
    }
    else if (!SetConsoleMode(conout, conmode = ((conmode | newoutmode)
                                                         & ~notoutmode))) {
        printerr("SetConsoleMode(CONOUT, 0x%x) failed (%d)\n", 
                 conmode, GetLastError());
    }

    conin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, 
                       FILE_SHARE_READ | FILE_SHARE_WRITE, 
                       FALSE, OPEN_EXISTING, 0, NULL);
    if (!conin || conin == INVALID_HANDLE_VALUE) {
        printerr("CreateFile(CONIN$) failed (%d)\n", GetLastError());
    }
    else if (!GetConsoleMode(conin, &conmode)) {
        printerr("GetConsoleMode(CONIN) failed (%d)\n", GetLastError());
    }
    else if (!SetConsoleMode(conin, conmode = ((conmode | newinmode) 
                                                        & ~notinmode))) {
        printerr("SetConsoleMode(CONIN, 0x%x) failed (%d)\n", 
                 conmode, GetLastError());
    }

    feed.in = conin;
    feed.out = hstdout;
    thread = CreateThread(NULL, 0, feedback, (LPVOID)&feed, 0, &tid);

    while (ReadFile(hstdin, str, sizeof(str), &len, NULL))
        if (!len || !WriteFile(conout, str, len, &len, NULL))
           break;

    printerr("[EOF] from stdin (%d)\n", GetLastError());

    CloseHandle(stdout);
    if (!GetConsoleTitle(str, sizeof(str))) {
        printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
    }
    else {
        strcat(str, " - [Finished]");
        if (!SetConsoleTitle(str)) {
            printerr("SetConsoleTitle() failed (%d)\n", GetLastError());
        }
    }

    WaitForSingleObject(thread, timeout);
    FreeConsole();
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
    feedback_args_t *feed = (feedback_args_t*)arg;
    char *str[1024];
    DWORD len;

    while (ReadFile(feed->in, str, sizeof(str), &len, NULL))
        if (!len || !WriteFile(feed->out, str, len, &len, NULL))
            break;

    printerr("[EOF] from Console (%d)\n", GetLastError());

    return 0;
}
