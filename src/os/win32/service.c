/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifdef WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <direct.h>

#include "httpd.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "http_main.h"
#include "multithread.h"
#include "service.h"
#include "registry.h"
#include "Win9xConHook.h"

#define SERVICE_APACHE_RESTART 128

static struct
{
    int (*main_fn)(int, char **);
    int connected;
    SERVICE_STATUS_HANDLE hServiceStatus;
    char *name;
    int exit_status;
    SERVICE_STATUS ssStatus;
    FILE *logFile;
} globdat;

/* statics for atexit processing or shared between threads */
static BOOL  die_on_logoff = FALSE;
static HWND  console_wnd = NULL;
static int   is_service = -1;

static void WINAPI service_main_fn(DWORD, LPTSTR *);
static void WINAPI service_ctrl(DWORD ctrlCode);
static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint);
static int ap_start_service(SC_HANDLE, DWORD argc, char **argv);
static int ap_stop_service(SC_HANDLE);
static int ap_restart_service(SC_HANDLE);

/* exit() for Win32 is macro mapped (horrible, we agree) that allows us 
 * to catch the non-zero conditions and inform the console process that
 * the application died, and hang on to the console a bit longer.
 *
 * The macro only maps for http_main.c and other sources that include
 * the service.h header, so we best assume it's an error to exit from
 * _any_ other module.
 *
 * If real_exit_code is not set to 2, it will not be set or trigger this
 * behavior on exit.  All service and child processes are expected to
 * reset this flag to zero to avoid undesireable side effects.  The value
 * 1 simply tells the system it is safe to enable the feature (set to 2),
 * while 0 prohibits the feature from being enabled.
 */
int real_exit_code = 1;

void hold_console_open_on_error(void)
{
    HANDLE hConIn;
    HANDLE hConErr;
    DWORD result;
    DWORD mode;
    time_t start;
    time_t remains;
    char *msg = "Note the errors or messages above, "
                "and press the <ESC> key to exit.  ";
    CONSOLE_SCREEN_BUFFER_INFO coninfo;
    INPUT_RECORD in;
    char count[16];

#ifdef WIN32
    /* The service parent cannot just 'pop' out of the main thread,
     * as it is about to try to do...
     * We must end this thread properly so the service control
     * thread exits gracefully.  atexit()s registered in the running
     * apache_main thread _should_ have already been handled, so now
     * we can exit this thread and allow the service thread to exit.
     */
    if (isWindowsNT() && isProcessService() && globdat.connected) {
        service_set_status(SERVICE_STOPPED);
        ExitThread(0);
    }
#endif

    if (!real_exit_code)
        return;
    hConIn = GetStdHandle(STD_INPUT_HANDLE);
    hConErr = GetStdHandle(STD_ERROR_HANDLE);
    if ((hConIn == INVALID_HANDLE_VALUE) || (hConErr == INVALID_HANDLE_VALUE))
        return;
    if (!WriteConsole(hConErr, msg, strlen(msg), &result, NULL) || !result)
        return;
    if (!GetConsoleScreenBufferInfo(hConErr, &coninfo))
        return;
    if (isWindowsNT())
        mode = ENABLE_MOUSE_INPUT | 0x80;
    else
        mode = ENABLE_MOUSE_INPUT;
    if (!SetConsoleMode(hConIn, mode))
        return;
        
    start = time(NULL);
    do
    {
        while (PeekConsoleInput(hConIn, &in, 1, &result) && result)
        {
            if (!ReadConsoleInput(hConIn, &in, 1, &result) || !result)
                return;
            if ((in.EventType == KEY_EVENT) && in.Event.KeyEvent.bKeyDown 
                    && (in.Event.KeyEvent.uChar.AsciiChar == 27))
                return;
            if (in.EventType == MOUSE_EVENT 
                    && (in.Event.MouseEvent.dwEventFlags == DOUBLE_CLICK))
                return;
        }
        remains = ((start + 30) - time(NULL)); 
        sprintf (count, "%d...", remains);
        if (!SetConsoleCursorPosition(hConErr, coninfo.dwCursorPosition))
            return;
        if (!WriteConsole(hConErr, count, strlen(count), &result, NULL) 
                || !result)
            return;
    }
    while ((remains > 0) && WaitForSingleObject(hConIn, 1000) != WAIT_FAILED);
}

/* Console Control handler for processing Ctrl-C/Ctrl-Break and
 * on Windows NT also user logoff and system shutdown,
 * this also used for the Win9x hidden service and child process
 */
static BOOL CALLBACK ap_control_handler(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                         "Ctrl+C/Break initiated, shutting down server.");

            real_exit_code = 0;
            /* for Interrupt signals, shut down the server.
             * Tell the system we have dealt with the signal
             * without waiting for Apache to terminate.
             */
            ap_start_shutdown();
            return TRUE;

        case CTRL_LOGOFF_EVENT:
            if (!die_on_logoff)
                return TRUE;
            /* or fall through... */

        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                         "Close/Logoff/Shutdown initiated, shutting down server.");

            /* for Terminate signals, shut down the server.
             * Wait for Apache to terminate, but respond
             * after a reasonable time to tell the system
             * that we have already tried to shut down.
             */
            real_exit_code = 0;
            fprintf(stderr, "Apache server shutdown initiated...\n");
            ap_start_shutdown();
            Sleep(30000);
            return TRUE;
    }
 
    /* We should never get here, but this is (mostly) harmless */
    return FALSE;
}

/* Once we are running a child process in our tty, it can no longer 
 * determine which console window is our own, since the window
 * reports that it is owned by the child process.
 */
static BOOL CALLBACK EnumttyWindow(HWND wnd, LPARAM retwnd)
{
    char tmp[20], *tty;
    if (isWindowsNT())
        tty = "ConsoleWindowClass";
    else
        tty = "tty";
    if (GetClassName(wnd, tmp, sizeof(tmp)) && !strcmp(tmp, tty)) 
    {
        DWORD wndproc, thisproc = GetCurrentProcessId();
        GetWindowThreadProcessId(wnd, &wndproc);
        if (wndproc == thisproc) {
            *((HWND*)retwnd) = wnd;
            return FALSE;
        }
    }
    return TRUE;
}

void stop_child_monitor(void)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Unhooking the child process monitor for shutdown.");

    FixConsoleCtrlHandler(ap_control_handler, 0);
}

/*
 * The Win32 Apache child cannot loose its console since 16bit cgi 
 * processes will hang (9x) or fail (NT) if they are not launched 
 * from a 32bit console app into that app's console window.  
 * Mark the 9x child as a service process and let the parent process 
 * clean it up as necessary.
 */
void ap_start_child_console(int is_child_of_service)
{
    int maxwait = 100;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Hooking up the child process monitor to watch for shutdown.");

    /* The child is never exactly a service */
    is_service = 0;
    
    /* Prevent holding open the (hidden) console */
    real_exit_code = 0;

    /* We only die on logoff if we not a service's child */
    die_on_logoff = !is_child_of_service;

    if (isWindowsNT()) {
        if (!is_child_of_service) {
            /*
             * Console mode Apache/WinNT needs to detach from the parent
             * console and create and hide it's own console window.
             * Not only is logout and shutdown more stable under W2K,
             * but this eliminates the mystery 'flicker' that users see
             * when invoking CGI apps (e.g. the titlebar or icon of the
             * console window changing to the cgi process's identifiers.)
             */
            FreeConsole();
            AllocConsole();
            EnumWindows(EnumttyWindow, (long)(&console_wnd));
            if (console_wnd)
                ShowWindow(console_wnd, SW_HIDE);
        }
        /*
         * Apache/WinNT installs no child console handler, otherwise
         * logoffs interfere with the service's child process!
         * The child process must have a later shutdown priority
         * than the parent, or the parent cannot shut down the
         * child process properly.  (The parent's default is 0x280.)
         */
        SetProcessShutdownParameters(0x200, 0);
        return;
    }

    if (!is_child_of_service) {
        FreeConsole();
        AllocConsole();
    }
    while (!console_wnd && maxwait-- > 0) { 
        EnumWindows(EnumttyWindow, (long)(&console_wnd));
        Sleep(100);
    }
    if (console_wnd) {
        FixConsoleCtrlHandler(ap_control_handler, die_on_logoff ? 1 : 2);
        ShowWindow(console_wnd, SW_HIDE);
        atexit(stop_child_monitor);
    }
}


void stop_console_monitor(void)
{
    /* Remove the control handler at the end of the day. */
    SetConsoleCtrlHandler(ap_control_handler, FALSE);

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Unhooking the console monitor for shutdown.");

    if (!isWindowsNT())
        FixConsoleCtrlHandler(ap_control_handler, 0);
}

void ap_start_console_monitor(void)
{
    HANDLE console_input;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Hooking up the console monitor to watch for shutdown.");

    die_on_logoff = TRUE;

    is_service = 0;

    console_input = GetStdHandle(STD_INPUT_HANDLE);
    /* Assure we properly accept Ctrl+C as an interrupt...
     * Win/2000 definately makes some odd assumptions about 
     * ctrl+c and the reserved console mode bits!
     */
    if (console_input != INVALID_HANDLE_VALUE)
    {
        /* The SetConsoleCtrlHandler(NULL... would fault under Win9x 
         * WinNT also includes an undocumented 0x80 bit for console mode
         * that preserves the console window behavior, and prevents the
         * bogus 'selection' mode from being accedently triggered.
         */
        if (isWindowsNT()) {
	    SetConsoleCtrlHandler(NULL, FALSE);
            SetConsoleMode(console_input, ENABLE_LINE_INPUT 
                                        | ENABLE_ECHO_INPUT 
                                        | ENABLE_PROCESSED_INPUT
                                        | 0x80);
        }
	else {
            SetConsoleMode(console_input, ENABLE_LINE_INPUT 
                                        | ENABLE_ECHO_INPUT 
                                        | ENABLE_PROCESSED_INPUT);
        }
    }
    
    if (!isWindowsNT())
        FixConsoleCtrlHandler(ap_control_handler, die_on_logoff ? 1 : 2);

    SetConsoleCtrlHandler(ap_control_handler, TRUE);

    atexit(stop_console_monitor);
}

void stop_service_monitor(void)
{
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Unhooking up the service monitor for shutdown.");

    Windows9xServiceCtrlHandler(ap_control_handler, FALSE);
}

int service95_main(int (*main_fn)(int, char **), int argc, char **argv, 
		   char *display_name)
{
    /* Windows 95/98 */
    char *service_name;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Hooking up the service monitor to watch for shutdown.");

    is_service = 1;
    die_on_logoff = FALSE;

    /* Set up the Win9x server name, as WinNT would */
    ap_server_argv0 = globdat.name = display_name;

    /* Remove spaces from display name to create service name */
    service_name = strdup(display_name);
    ap_remove_spaces(service_name, display_name);

    /* Prevent holding open the (hidden) console */
    real_exit_code = 0;

    Windows9xServiceCtrlHandler(ap_control_handler, service_name);

    atexit(stop_service_monitor);
    
    /* Run the service */
    globdat.exit_status = main_fn(argc, argv);

    return (globdat.exit_status);
}

static HANDLE eventlog_pipewrite = NULL;
static HANDLE eventlog_thread = NULL;

int service_main(int (*main_fn)(int, char **), int argc, char **argv )
{
    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "", service_main_fn },
        { NULL, NULL }
    };

    /* Prevent holding open the (nonexistant) console and allow us past
     * the first NT service to parse the service's args in apache_main() 
     */
    ap_server_argv0 = argv[0];
    real_exit_code = 0;

    /* keep the server from going to any real effort, since we know */
    is_service = 1;

    globdat.main_fn = main_fn;
    globdat.connected = 1;

    if(!StartServiceCtrlDispatcher(dispatchTable))
    {
        /* This is a genuine failure of the SCM. */
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                     "Error starting service control dispatcher");
    }

    globdat.connected = 0;

    if (eventlog_pipewrite)
    {
        CloseHandle(eventlog_pipewrite);
        WaitForSingleObject(eventlog_thread, 10000);
        eventlog_pipewrite = NULL;
    }

    return(globdat.exit_status);
}

long __stdcall service_stderr_thread(LPVOID hPipe)
{
    HANDLE hPipeRead = (HANDLE) hPipe;
    HANDLE hEventSource;
    char errbuf[256];
    char *errmsg = errbuf;
    char *errarg[9];
    DWORD errlen = 0;
    DWORD errres;
    HKEY hk;
    
    errarg[0] = "The Apache service named";
    errarg[1] = ap_server_argv0;
    errarg[2] = "reported the following error:\r\n>>>";
    errarg[3] = errmsg;
    errarg[4] = "<<<\r\n before the error.log file could be opened.\r\n";
    errarg[5] = "More information may be available in the error.log file.";
    errarg[6] = NULL;
    errarg[7] = NULL;
    errarg[8] = NULL;
    
    /* What are we going to do in here, bail on the user?  not. */
    if (!RegCreateKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"
                      "\\EventLog\\Application\\Apache Service", &hk)) 
    {
        /* The stock message file */
        char *netmsgkey = "%SystemRoot%\\System32\\netmsg.dll";
        DWORD dwData = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | 
                       EVENTLOG_INFORMATION_TYPE; 
 
        RegSetValueEx(hk, "EventMessageFile", 0, REG_EXPAND_SZ,
                          (LPBYTE) netmsgkey, strlen(netmsgkey) + 1);
        
        RegSetValueEx(hk, "TypesSupported", 0, REG_DWORD,
                          (LPBYTE) &dwData, sizeof(dwData));
        RegCloseKey(hk);
    }

    hEventSource = RegisterEventSource(NULL, "Apache Service");

    while (ReadFile(hPipeRead, errmsg, 1, &errres, NULL) && (errres == 1))
    {
        if ((errmsg > errbuf) || !isspace(*errmsg))
        {
            ++errlen;
            ++errmsg;
            if ((*(errmsg - 1) == '\n') || (errlen == sizeof(errbuf) - 1))
            {
                while (errlen && isspace(errbuf[errlen - 1]))
                    --errlen;
                errbuf[errlen] = '\0';

                /* Generic message: '%1 %2 %3 %4 %5 %6 %7 %8 %9'
                 * The event code in netmsg.dll is 3299
                 */
                ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, 
                            3299, NULL, 9, 0, errarg, NULL);
                errmsg = errbuf;
                errlen = 0;
            }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                 "Shut down the Service Error Event Logger.");

    CloseHandle(eventlog_pipewrite);
    eventlog_pipewrite = NULL;
    
    CloseHandle(hPipeRead);

    CloseHandle(eventlog_thread);
    eventlog_thread = NULL;
    return 0;
}

void __stdcall service_main_fn(DWORD argc, LPTSTR *argv)
{
    HANDLE hCurrentProcess;
    HANDLE hPipeRead = NULL;
    HANDLE hPipeReadDup;
    HANDLE hNullFile;
    DWORD  threadid;
    SECURITY_ATTRIBUTES sa = {0};
    char **newargv;

    if(!(globdat.hServiceStatus = RegisterServiceCtrlHandler(argv[0], 
                                                             service_ctrl)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "Failure registering service handler");
        return;
    }

    ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000);                 // wait hint

    /* Create a pipe to send stderr messages to the system error log */
    hCurrentProcess = GetCurrentProcess();
    if (CreatePipe(&hPipeRead, &eventlog_pipewrite, &sa, 0)) 
    {
        if (DuplicateHandle(hCurrentProcess, hPipeRead, hCurrentProcess,
                            &hPipeReadDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            CloseHandle(hPipeRead);
            hPipeRead = hPipeReadDup;
            eventlog_thread = CreateThread(NULL, 0, service_stderr_thread, 
                                           (LPVOID) hPipeRead, 0, &threadid);
            if (eventlog_thread)
            {
                int fh;
                FILE *fl;
            	fflush(stderr);
		SetStdHandle(STD_ERROR_HANDLE, eventlog_pipewrite);
				
                fh = _open_osfhandle((long) STD_ERROR_HANDLE, 
                                     _O_WRONLY | _O_BINARY);
                dup2(fh, STDERR_FILENO);
                fl = _fdopen(STDERR_FILENO, "wcb");
                memcpy(stderr, fl, sizeof(FILE));
            }
            else
            {
                CloseHandle(hPipeRead);
                CloseHandle(eventlog_pipewrite);
                eventlog_pipewrite = NULL;
            }            
        }
        else
        {
            CloseHandle(hPipeRead);
            CloseHandle(eventlog_pipewrite);
            eventlog_pipewrite = NULL;
        }            
    }

    /* Open a null handle to nak our stdin */
    hNullFile = CreateFile("nul", GENERIC_READ | GENERIC_WRITE, 
                           FILE_SHARE_READ | FILE_SHARE_WRITE, 
                           &sa, OPEN_EXISTING, 0, NULL);
    if (hNullFile == INVALID_HANDLE_VALUE) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, NULL,
                     "Parent: Unable to create null stdin pipe for this service process.\n");
    }
    else {
        int fh;
        FILE *fl;
        fflush(stdin);
	SetStdHandle(STD_INPUT_HANDLE, hNullFile);
        fh = _open_osfhandle((long) STD_INPUT_HANDLE, 
                             _O_RDONLY | _O_BINARY);
        dup2(fh, STDIN_FILENO);
        fl = _fdopen(STDIN_FILENO, "rcb");
        memcpy(stdin, fl, sizeof(FILE));
    }

    /* Open a null handle to soak our stdout */
    hNullFile = CreateFile("nul", GENERIC_READ | GENERIC_WRITE, 
                           FILE_SHARE_READ | FILE_SHARE_WRITE, 
                           &sa, OPEN_EXISTING, 0, NULL);
    if (hNullFile == INVALID_HANDLE_VALUE) {
        ap_log_error(APLOG_MARK, APLOG_WIN32ERROR | APLOG_CRIT, NULL,
                     "Parent: Unable to create null stdout pipe for this service process.\n");
    }
    else {
        int fh;
        FILE *fl;
        fflush(stdout);
	SetStdHandle(STD_OUTPUT_HANDLE, hNullFile);
        fh = _open_osfhandle((long) STD_OUTPUT_HANDLE, 
                             _O_WRONLY | _O_BINARY);
        dup2(fh, STDOUT_FILENO);
        fl = _fdopen(STDOUT_FILENO, "wcb");
        memcpy(stdout, fl, sizeof(FILE));
    }

    /* Grab it or lose it */
    globdat.name = argv[0];

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
             "Hooked up the Service Error Event Logger.");

    /* Fold the "Start Parameters" in with the true executable argv[0],
     * and insert a -n tag to pass the service name from the SCM's argv[0]
     */
    newargv = (char**) malloc((argc + 3) * sizeof(char*));
    newargv[0] = ap_server_argv0;  /* The true executable name */
    newargv[1] = "-n";             /* True service name follows (argv[0]) */
    memcpy (newargv + 2, argv, argc * sizeof(char*));
    newargv[argc + 2] = NULL;      /* SCM doesn't null terminate the array */
    argv = newargv;
    argc += 2;

    /* Use the name of the service as the error log marker */
    ap_server_argv0 = globdat.name;

    globdat.exit_status = globdat.main_fn( argc, argv );
}

/* Set the service description regardless of platform.
 * We revert to set_service_description_string on NT/9x, the
 * very long way so any Apache management program can grab the
 * description.  This would be bad on Win2000, since it wouldn't
 * notify the service control manager of the name change.
 */
static void set_service_description_string(const char *description)
{
    char szPath[MAX_PATH];
    HKEY hkey;

    /* Create/Find the Service key that Monitor Applications iterate */
    ap_snprintf(szPath, sizeof(szPath), 
                "SYSTEM\\CurrentControlSet\\Services\\%s", globdat.name);
    ap_remove_spaces(szPath, szPath);
    if (RegCreateKey(HKEY_LOCAL_MACHINE, szPath, &hkey) != ERROR_SUCCESS) {
        return;
    }

    /* Attempt to set the Description value for our service */
    RegSetValueEx(hkey, "Description", 0, REG_SZ,  
                  (unsigned char *) description, 
                  strlen(description) + 1);
    RegCloseKey(hkey);
}


char *get_service_name(char *display_name)
{
    /* Get the service's true name from the SCM on NT/2000, since it
     * can be changed by the user on 2000, especially, from the
     * service control panel.  We can't trust the service name to 
     * match a space-collapsed display name.
     */
    char service_name[MAX_PATH];
    if (isWindowsNT())
    {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        DWORD namelen = sizeof(service_name);
        if (scm) {
            BOOL ok = GetServiceKeyName(scm, display_name, service_name, 
                                        &namelen);
            CloseServiceHandle(scm);
            if (ok)
                return strdup(service_name);
        }
    }
    ap_remove_spaces(service_name, display_name);
    return strdup(service_name);
}


char *get_display_name(char *service_name)
{
    /* Get the service's display name from the SCM on NT/2000, since it
     * can be changed by the user on 2000, especially, from the
     * service control panel.  We can't trust the service name as
     * provided by the user.
     */
    if (isWindowsNT())
    {
        char display_name[MAX_PATH];
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        DWORD namelen = sizeof(display_name);
        if (scm) {
            BOOL ok = GetServiceDisplayName(scm, service_name, display_name,
                                            &namelen);
            CloseServiceHandle(scm);
            if (ok)
                return strdup(display_name);
        }
    }
    return service_name;
}


/* ChangeServiceConfig2() prototype:
 */
typedef WINADVAPI BOOL (WINAPI *CSD_T)(SC_HANDLE, DWORD, LPCVOID);


/* Windows 2000 alone supports ChangeServiceConfig2 in order to
 * register our server_version string... so we need some fixups
 * to avoid binding to that function if we are on WinNT/9x.
 * Fall back on set_service_description_string if we fail.
 */
void service_set_status(int status)
{
    const char *full_description;
    SC_HANDLE schSCManager;
    CSD_T ChangeServiceDescription;
    HANDLE hwin2000scm;
    BOOL ret = 0;

    /* Nothing to do if we are a console
     */
    if (!is_service)
        return;

    ReportStatusToSCMgr(status, NO_ERROR, 3000);

    if (status != SERVICE_RUNNING)
        return;

    /* Time to fix up the description, upon each successful restart
     */
    full_description = ap_get_server_version();
    hwin2000scm = GetModuleHandle("ADVAPI32.DLL");
    if (!hwin2000scm) {
        set_service_description_string(full_description);
        return;
    }
    ChangeServiceDescription = (CSD_T) GetProcAddress(hwin2000scm, 
                                                      "ChangeServiceConfig2A");
    if (!ChangeServiceDescription) {
        set_service_description_string(full_description);
        return;
    }
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        SC_HANDLE schService = OpenService(schSCManager, globdat.name,
                                           SERVICE_ALL_ACCESS);
        if (schService) {
            ret = ChangeServiceDescription(schService,
                                           1 /* SERVICE_CONFIG_DESCRIPTION */,
                                           &full_description);
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }
    if (!ret)
        set_service_description_string(full_description);
}


//
//  FUNCTION: service_ctrl
//
//  PURPOSE: This function is called by the SCM whenever
//           ControlService() is called on this service.
//
//  PARAMETERS:
//    dwCtrlCode - type of control requested
//
//  RETURN VALUE:
//    none
//
//  COMMENTS:  See the user-defined Handler() entry in the PSDK
//
VOID WINAPI service_ctrl(DWORD dwCtrlCode)
{
    switch(dwCtrlCode)
    {
        // Stop the service.
        //
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                         "Service Stop/Shutdown signaled, shutting down server.");
            ReportStatusToSCMgr(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            ap_start_shutdown();
            break;

        case SERVICE_APACHE_RESTART:
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, NULL,
                         "Service Restart signaled, shutting down server.");
            ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 15000);
            ap_start_restart(1);
            break;

        // Update the service status.
        //
        case SERVICE_CONTROL_INTERROGATE:
            ReportStatusToSCMgr(globdat.ssStatus.dwCurrentState, NO_ERROR, 0);
            break;

        // invalid control code, ignored
        //
        default:
            break;
    }
}


int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint)
{
    static int firstTime = 1;
    static int checkPoint = 1;
    int rv;
    
    if (firstTime)
    {
        firstTime = 0;
        globdat.ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        globdat.ssStatus.dwServiceSpecificExitCode = 0;
        globdat.ssStatus.dwCheckPoint = 1;
    }

    if (globdat.connected)
    {
        if ((currentState == SERVICE_START_PENDING)
         || (currentState == SERVICE_STOP_PENDING))
            globdat.ssStatus.dwControlsAccepted = 0;
        else
            globdat.ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP 
                                                | SERVICE_ACCEPT_SHUTDOWN;

        globdat.ssStatus.dwCurrentState = currentState;
        globdat.ssStatus.dwWin32ExitCode = exitCode;

        if ( ( currentState == SERVICE_RUNNING ) ||
             ( currentState == SERVICE_STOPPED ) )
        {
            globdat.ssStatus.dwWaitHint = 0;
            globdat.ssStatus.dwCheckPoint = 0;
        }
        else 
        {
            if(waitHint)
                globdat.ssStatus.dwWaitHint = waitHint;
            globdat.ssStatus.dwCheckPoint = ++checkPoint;
        }

        rv = SetServiceStatus(globdat.hServiceStatus, &globdat.ssStatus);
    }
    return(1);
}

void InstallService(pool *p, char *display_name, int argc, char **argv, int reconfig)
{
    TCHAR szPath[MAX_PATH];
    TCHAR szQuotedPath[512];
    char *service_name;
    int regargc = 0;
    char default_depends[] = "Tcpip\0Afd\0";
    char *depends = default_depends;
    size_t depends_len = sizeof(default_depends);
    char **regargv = malloc((argc + 4) * sizeof(char*));
    char **newelem = regargv;

    regargc += 4;
    *(newelem++) = "-d";
    *(newelem++) = ap_server_root;
    *(newelem++) = "-f";
    *(newelem++) = ap_server_confname;

    while (++argv, --argc) {
        if ((**argv == '-') && strchr("kndf", argv[0][1]))
            --argc, ++argv; /* Skip already handled -k -n -d -f options */
        else if ((**argv == '-') && (argv[0][1] == 'W')) 
        {
            /* Catch this service -W dependency 
             * the depends list is null seperated, double-null terminated
             */
            char *service = get_service_name(*(argv + 1));
            size_t add_len = strlen(service) + 1;
            char *more_depends = malloc(depends_len + add_len);
            memcpy (more_depends, depends, depends_len - 1);
            memcpy (more_depends + depends_len - 1, service, add_len);
            depends_len += add_len;
            depends = more_depends;
            depends[depends_len - 1] = '\0';
            ++argv, --argc;
        }
        else if ((**argv != '-') || !strchr("iuw", argv[0][1]))
            *(newelem++) = *argv, ++regargc;  /* Ignoring -i -u -w options */
    }

    /* Remove spaces from display name to create service name */
    service_name = get_service_name(display_name);
    
    printf(reconfig ? "Reconfiguring the %s service\n"
                    : "Installing the %s service\n", 
           display_name);

    if (GetModuleFileName( NULL, szPath, 512 ) == 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "GetModuleFileName failed");
        return;
    }

    if (isWindowsNT())
    {
        SC_HANDLE schService;
        SC_HANDLE schSCManager;

        ap_snprintf(szQuotedPath, sizeof(szQuotedPath), "\"%s\" --ntservice", szPath);

        schSCManager = OpenSCManager(
                            NULL,                 // machine (local)
                            NULL,                 // database (default)
                            SC_MANAGER_ALL_ACCESS // access required
                            );
        if (!schSCManager) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "OpenSCManager failed");
            return;
        }
        
        /* Added dependencies for the following: TCPIP, AFD
         * AFD is the winsock handler, TCPIP is self evident
         *
         * RPCSS is the Remote Procedure Call (RPC) Locator
         * required for DCOM communication.  I am far from
         * convinced we should toggle this, but be warned that
         * future apache modules or ISAPI dll's may depend on it.
         * Also UNC share users may need the networking service 
         * started (usually "LanmanWorkstation").  "ProtectedStorage" 
         * may be needed depending on how files and registry keys are 
         * stored.  And W3SVC may be needed to wait until IIS has
         * glommed and released 0.0.0.0:80 if the admin allocates 
         * two different IP's to Apache and IIS on the same port.
         */
        if (reconfig) 
        {
            schService = OpenService(schSCManager, service_name, 
                                     SERVICE_ALL_ACCESS);
            if (!schService)
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL, 
                             "OpenService failed");
            else if (!ChangeServiceConfig(
                        schService,                 // Service handle
                        SERVICE_WIN32_OWN_PROCESS,  // service type
                        SERVICE_AUTO_START,         // start type
                        SERVICE_ERROR_NORMAL,       // error control type
                        szQuotedPath,               // service's binary
                        NULL,                       // no load ordering group
                        NULL,                       // no tag identifier
                        depends,                    // dependencies
                        NULL,                       // user account
                        NULL,                       // account password
                        display_name)) {            // service display name
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL, 
		             "ChangeServiceConfig failed");
                /* !schService aborts configuration below */
                CloseServiceHandle(schService);
                schService = NULL;
            }
        }
        else /* !reconfig */
        {
            schService = CreateService(
                        schSCManager,               // SCManager database
                        service_name,               // name of service
                        display_name,               // name to display
                        SERVICE_ALL_ACCESS,         // desired access
                        SERVICE_WIN32_OWN_PROCESS,  // service type
                        SERVICE_AUTO_START,         // start type
                        SERVICE_ERROR_NORMAL,       // error control type
                        szQuotedPath,               // service's binary
                        NULL,                       // no load ordering group
                        NULL,                       // no tag identifier
                        depends,                    // dependencies
                        NULL,                       // user account
                        NULL);                      // account password
            if (!schService)
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL, 
                             "CreateService failed");
        }
        if (schService)
            CloseServiceHandle(schService);
        
        CloseServiceHandle(schSCManager);
        
        if (!schService)
            return;
    }
    else /* !isWindowsNT() */
    {
        HKEY hkey;
        DWORD rv;

        ap_snprintf(szQuotedPath, sizeof(szQuotedPath),
                    "\"%s\" -k start -n %s", 
                    szPath, service_name);
        /* Create/Find the RunServices key */
        rv = RegCreateKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows"
                          "\\CurrentVersion\\RunServices", &hkey);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Could not create/open the RunServices registry key");
            return;
        }

        /* Attempt to add the value for our service */
        rv = RegSetValueEx(hkey, service_name, 0, REG_SZ, 
                           (unsigned char *)szQuotedPath, 
                           strlen(szQuotedPath) + 1);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Unable to install service: "
                         "Could not add to RunServices Registry Key");
            RegCloseKey(hkey);
            return;
        }

        RegCloseKey(hkey);

        /* Create/Find the Service key for Monitor Applications to iterate */
        ap_snprintf(szPath, sizeof(szPath), 
                    "SYSTEM\\CurrentControlSet\\Services\\%s", service_name);
        rv = RegCreateKey(HKEY_LOCAL_MACHINE, szPath, &hkey);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Could not create/open the %s registry key", szPath);
            return;
        }

        /* Attempt to add the ImagePath value to identify it as Apache */
        rv = RegSetValueEx(hkey, "ImagePath", 0, REG_SZ, 
                           (unsigned char *)szQuotedPath, 
                           strlen(szQuotedPath) + 1);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Unable to install service: "
                         "Could not add ImagePath to %s Registry Key", 
                         service_name);
            RegCloseKey(hkey);
            return;
        }

        /* Attempt to add the DisplayName value for our service */
        rv = RegSetValueEx(hkey, "DisplayName", 0, REG_SZ, 
                           (unsigned char *)display_name, 
                           strlen(display_name) + 1);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Unable to install service: "
                         "Could not add DisplayName to %s Registry Key", 
                         service_name);
            RegCloseKey(hkey);
            return;
        }

        RegCloseKey(hkey);
    }

    /* Both Platforms: Now store the args in the registry */
    if (ap_registry_set_service_args(p, regargc, regargv, service_name)) {
        return;
    }

    printf("The %s service has been %s successfully.\n", 
           display_name, reconfig ? "reconfigured" : "installed");
}

void RemoveService(char *display_name)
{
    char *service_name;
    BOOL success = FALSE;

    printf("Removing the %s service\n", display_name);

    /* Remove spaces from display name to create service name */
    service_name = get_service_name(display_name);
    
    if (isWindowsNT())
    {
        SC_HANDLE   schService;
        SC_HANDLE   schSCManager;
    
        schSCManager = OpenSCManager(
                            NULL,                   // machine (NULL == local)
                            NULL,                   // database (NULL == default)
                            SC_MANAGER_ALL_ACCESS   // access required
                            );
        if (!schSCManager) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "OpenSCManager failed");
            return;
        }

        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "OpenService failed");
        }
        else {
            /* try to stop the service */
            ap_stop_service(schService);

            // now remove the service
            if (DeleteService(schService) == 0)
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                             "DeleteService failed");
            else
                success = TRUE;
            CloseServiceHandle(schService);
        }
        /* SCM removes registry parameters  */
        CloseServiceHandle(schSCManager);
    }
    else /* !isWindowsNT() */
    {
        HKEY hkey;
        DWORD service_pid;
        DWORD rv;
        HWND hwnd;

        /* Locate the named window of class ApacheWin95ServiceMonitor
         * from the active top level windows
         */
        hwnd = FindWindow("ApacheWin95ServiceMonitor", service_name);
        if (hwnd && GetWindowThreadProcessId(hwnd, &service_pid))
        {
            int ticks = 120;
            char prefix[20];
            ap_snprintf(prefix, sizeof(prefix), "ap%ld", (long)service_pid);
            setup_signal_names(prefix);
            ap_start_shutdown();
            while (--ticks) {
                if (!IsWindow(hwnd))
                    break;
                Sleep(1000);
            }
        }

        /* Open the RunServices key */
        rv = RegOpenKey(HKEY_LOCAL_MACHINE, 
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                    &hkey);
        if (rv != ERROR_SUCCESS) {
            SetLastError(rv);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Could not open the RunServices registry key.");
        } 
        else {
            /* Delete the registry value for this service */
            rv = RegDeleteValue(hkey, service_name);
            if (rv != ERROR_SUCCESS) {
                SetLastError(rv);
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                             "Unable to remove service: "
                             "Could not delete the RunServices entry.");
            }
            else
                success = TRUE;
        }
        RegCloseKey(hkey);

        /* Open the Services key */
        rv = RegOpenKey(HKEY_LOCAL_MACHINE, 
                        "SYSTEM\\CurrentControlSet\\Services", &hkey);
        if (rv != ERROR_SUCCESS) {
            rv = RegDeleteValue(hkey, service_name);
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "Could not open the Services registry key.");
            success = FALSE;
        } 
        else {
            /* Delete the registry key for this service */
            rv = RegDeleteKey(hkey, service_name);
            if (rv != ERROR_SUCCESS) {
                SetLastError(rv);
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                             "Unable to remove service: "
                             "Could not delete the Services registry key.");
                success = FALSE;
            }
        }
        RegCloseKey(hkey);
    }
    if (success)
        printf("The %s service has been removed successfully.\n", 
               display_name);
}


BOOL isWindowsNT(void)
{
    static BOOL once = FALSE;
    static BOOL isNT = FALSE;
    
    if (!once)
    {
        OSVERSIONINFO osver;
        osver.dwOSVersionInfoSize = sizeof(osver);
        if (GetVersionEx(&osver))
            if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
                isNT = TRUE;
        once = TRUE;
    }
    return isNT;
}


/*
 * A hack to determine if we're running as a service without waiting for
 * the SCM to fail.
 */

BOOL isProcessService() 
{
    if (is_service != -1)
        return is_service;
    if (!isWindowsNT() || !AllocConsole()) {
        /* Don't assume anything, just yet */
        return FALSE;
    }
    FreeConsole();
    is_service = 1;
    return TRUE;
}

/* Determine is service_name is a valid service
 *
 * TODO: be nice if we tested that it is an 'apache' service, no?
 */

BOOL isValidService(char *display_name) {
    char service_key[MAX_PATH];
    char *service_name;
    HKEY hkey;
    
    /* Remove spaces from display name to create service name */
    strcpy(service_key, "System\\CurrentControlSet\\Services\\");
    service_name = get_service_name(display_name);
    strcat(service_key, service_name);

    if (RegOpenKey(HKEY_LOCAL_MACHINE, service_key, &hkey) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegCloseKey(hkey);
    return TRUE;
}


int send_signal_to_service(char *display_name, char *sig, 
                           int argc, char **argv)
{
    DWORD       service_pid;
    HANDLE      hwnd;
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;
    char       *service_name;
    int success = FALSE;

    enum                        { start,      restart,      stop, unknown } action;
    static char *param[] =      { "start",    "restart",    "shutdown" };
    static char *participle[] = { "starting", "restarting", "stopping" };
    static char *past[]       = { "started",  "restarted",  "stopped"  };

    for (action = start; action < unknown; action++)
        if (!strcasecmp(sig, param[action]))
            break;

    if (action == unknown) {
        printf("signal must be start, restart, or shutdown\n");
        return FALSE;
    }

    service_name = get_service_name(display_name);

    if (isWindowsNT()) 
    {
        schSCManager = OpenSCManager(
                            NULL,                   // machine (NULL == local)
                            NULL,                   // database (NULL == default)
                            SC_MANAGER_ALL_ACCESS   // access required
                            );
        if (!schSCManager) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "OpenSCManager failed");
            return FALSE;
        }
        
        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "OpenService failed");
            CloseServiceHandle(schSCManager);
            return FALSE;
        }
        
        if (!QueryServiceStatus(schService, &globdat.ssStatus)) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                         "QueryService failed");
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
        }
    }
    else /* !isWindowsNT() */
    {
        /* Locate the window named service_name of class ApacheWin95ServiceMonitor
         * from the active top level windows
         */
        hwnd = FindWindow("ApacheWin95ServiceMonitor", service_name);
        if (hwnd && GetWindowThreadProcessId(hwnd, &service_pid))
            globdat.ssStatus.dwCurrentState = SERVICE_RUNNING;
        else
            globdat.ssStatus.dwCurrentState = SERVICE_STOPPED;
    }

    if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED 
            && action == stop) {
        printf("The %s service is not started.\n", display_name);
        return FALSE;
    }
    else if (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING 
                 && action == start) {
        printf("The %s service has already been started.\n", display_name);
        strcpy(sig, "");
        return FALSE;
    }
    else
    {
        printf("The %s service is %s.\n", display_name, participle[action]);

        if (isWindowsNT()) 
        {
            if (action == stop)
                success = ap_stop_service(schService);
            else if ((action == start) 
                     || ((action == restart) 
                            && (globdat.ssStatus.dwCurrentState 
                                    == SERVICE_STOPPED)))
            {
                /* start NT service needs service args */
                char **args = malloc(argc * sizeof(char*));
                int i, j;
                for (i = 1, j = 0; i < argc; i++) {
                    if ((argv[i][0] == '-') && ((argv[i][1] == 'k') 
                                             || (argv[i][1] == 'n')))
                        ++i;
                    else
                        args[j++] = argv[i];
                }
                success = ap_start_service(schService, j, args);
            }
            else if (action == restart)
                success = ap_restart_service(schService);
        }
        else /* !isWindowsNT()) */
        {
            char prefix[20];
            ap_snprintf(prefix, sizeof(prefix), "ap%ld", (long)service_pid);
            setup_signal_names(prefix);

            if (action == stop) {
                int ticks = 60;
                ap_start_shutdown();
                while (--ticks)
                {
                    if (!IsWindow(hwnd)) {
                        success = TRUE;
                        break;
                    }
                    Sleep(1000);
                }
            }
            else if (action == restart) 
            {   
                /* This gets a bit tricky... start and restart (of stopped service)
                 * will simply fall through and *THIS* process will fade into an
                 * invisible 'service' process, detaching from the user's console.
                 * We need to change the restart signal to "start", however,
                 * if the service was not -yet- running, and we do return FALSE
                 * to assure main() that we haven't done anything yet.
                 */
                if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED) 
                {
                    printf("The %s service has %s.\n", display_name, 
                           past[action]);
                    strcpy(sig, "start");
                    return FALSE;
                }
                
                ap_start_restart(1);
                success = TRUE;
            }
            else /* action == start */
            {
                printf("The %s service is %s.\n", display_name, 
                       past[action]);
                return FALSE;
            }
        }

        if( success )
            printf("The %s service has %s.\n", display_name, past[action]);
        else
            printf("Failed to %s the %s service.\n", sig, display_name);
    }

    if (isWindowsNT()) {
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }
    return success;
}

int ap_stop_service(SC_HANDLE schService)
{
    if (ControlService(schService, SERVICE_CONTROL_STOP, &globdat.ssStatus)) {
        Sleep(1000);
        while (QueryServiceStatus(schService, &globdat.ssStatus)) {
            if (globdat.ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
                Sleep(1000);
            else
                break;
        }
    }
    if (QueryServiceStatus(schService, &globdat.ssStatus))
        if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED)
            return TRUE;
    return FALSE;
}

int ap_start_service(SC_HANDLE schService, DWORD argc, char **argv) {
    if (StartService(schService, argc, argv)) {
        Sleep(1000);
        while(QueryServiceStatus(schService, &globdat.ssStatus)) {
            if(globdat.ssStatus.dwCurrentState == SERVICE_START_PENDING)
                Sleep(1000);
            else
                break;
        }
    }
    if (QueryServiceStatus(schService, &globdat.ssStatus))
        if (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING)
            return TRUE;
    return FALSE;
}

int ap_restart_service(SC_HANDLE schService) 
{
    int ticks;
    if (ControlService(schService, SERVICE_APACHE_RESTART, &globdat.ssStatus)) 
    {
        ticks = 60;
        while (globdat.ssStatus.dwCurrentState == SERVICE_START_PENDING)
        {
            Sleep(1000);
            if (!QueryServiceStatus(schService, &globdat.ssStatus)) 
                return FALSE;
            if (!--ticks)
                break;
        }
    }
    if (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING)
        return TRUE;
    return FALSE;
}

#endif /* WIN32 */
