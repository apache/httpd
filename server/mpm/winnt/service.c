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

/* This module ALONE requires the window message API from user.h 
 * and the default APR include of windows.h will omit it, so
 * preload the API symbols now...
 */

#define CORE_PRIVATE 
#define _WINUSER_

#include "httpd.h"
#include "http_log.h"
#include "mpm_winnt.h"
#include "apr_strings.h"
#include "apr_lib.h"

#ifdef NOUSER
#undef NOUSER
#endif
#undef _WINUSER_
#include <winuser.h>

static char *mpm_service_name = NULL;
static char *mpm_display_name = NULL;

static struct
{
    HANDLE mpm_thread;       /* primary thread handle of the apache server */
    HANDLE service_thread;   /* thread service/monitor handle */
    DWORD  service_thread_id;/* thread service/monitor ID */
    HANDLE signal_monitor;   /* service monitor thread signal event */
    SERVICE_STATUS ssStatus;
    SERVICE_STATUS_HANDLE hServiceStatus;
} globdat;

static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint);

/* The service configuration's is stored under the following trees:
 *
 * HKLM\System\CurrentControlSet\Services\[service name]
 *
 *     \DisplayName
 *     \ImagePath
 *     \Parameters\ConfigArgs
 *
 * For Win9x, the launch service command is stored under:
 *
 * HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices\[service name]
 */


/* exit() for Win32 is macro mapped (horrible, we agree) that allows us 
 * to catch the non-zero conditions and inform the console process that
 * the application died, and hang on to the console a bit longer.
 *
 * The macro only maps for http_main.c and other sources that include
 * the service.h header, so we best assume it's an error to exit from
 * _any_ other module.
 *
 * If real_exit_code is reset to 0, it will not be set or trigger this
 * behavior on exit.  All service and child processes are expected to
 * reset this flag to zero to avoid undesireable side effects.
 */
int real_exit_code = 1;

void hold_console_open_on_error(void)
{
    HANDLE hConIn;
    HANDLE hConErr;
    DWORD result;
    time_t start;
    time_t remains;
    char *msg = "Note the errors or messages above, "
                "and press the <ESC> key to exit.  ";
    CONSOLE_SCREEN_BUFFER_INFO coninfo;
    INPUT_RECORD in;
    char count[16];
    
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
    if (!SetConsoleMode(hConIn, ENABLE_MOUSE_INPUT | 0x80))
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

static BOOL  die_on_logoff = FALSE;

static LRESULT CALLBACK monitor_service_9x_proc(HWND hWnd, UINT msg, 
                                                WPARAM wParam, LPARAM lParam)
{
/* This is the WndProc procedure for our invisible window.
 * When the user shuts down the system, this window is sent
 * a signal WM_ENDSESSION. We clean up by signaling Apache
 * to shut down, and idle until Apache's primary thread quits.
 */
    if ((msg == WM_ENDSESSION) 
            && (die_on_logoff || (lParam != ENDSESSION_LOGOFF)))
    {
        ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
	if (wParam)
            /* Don't leave this message until we are dead! */
	    WaitForSingleObject(globdat.mpm_thread, 30000);
        return 0;
    }
    return (DefWindowProc(hWnd, msg, wParam, lParam));
}

static DWORD WINAPI monitor_service_9x_thread(void *service_name)
{
    /* When running as a service under Windows 9x, there is no console
     * window present, and no ConsoleCtrlHandler to call when the system 
     * is shutdown.  If the WatchWindow thread is created with a NULL
     * service_name argument, then the ...SystemMonitor window class is
     * used to create the "Apache" window to watch for logoff and shutdown.
     * If the service_name is provided, the ...ServiceMonitor window class
     * is used to create the window named by the service_name argument,
     * and the logoff message is ignored.
     */
    WNDCLASS wc;
    HWND hwndMain;
    MSG msg;
    
    wc.style         = CS_GLOBALCLASS;
    wc.lpfnWndProc   = monitor_service_9x_proc; 
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0; 
    wc.hInstance     = NULL;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName  = NULL;
    if (service_name)
	wc.lpszClassName = "ApacheWin95ServiceMonitor";
    else
	wc.lpszClassName = "ApacheWin95SystemMonitor";
 
    die_on_logoff = service_name ? FALSE : TRUE;

    if (!RegisterClass(&wc)) 
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), 
                     NULL, "Could not register window class for WatchWindow");
        SetEvent(globdat.signal_monitor);
        globdat.service_thread_id = 0;
        return 0;
    }
    
    /* Create an invisible window */
    hwndMain = CreateWindow(wc.lpszClassName, 
                            service_name ? (char *) service_name : "Apache",
 	                    WS_OVERLAPPEDWINDOW & ~WS_VISIBLE, 
                            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
                            CW_USEDEFAULT, NULL, NULL, NULL, NULL);
                            
    if (!hwndMain)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), 
                     NULL, "Could not create WatchWindow");
        SetEvent(globdat.signal_monitor);
        globdat.service_thread_id = 0;
        return 0;
    }

    /* If we succeed, eliminate the console window.
     * Signal the parent we are all set up, and
     * watch the message queue while the window lives.
     */
    FreeConsole();
    SetEvent((HANDLE) globdat.signal_monitor);
    while (GetMessage(&msg, NULL, 0, 0)) 
    {
        if (msg.message == WM_CLOSE)
            DestroyWindow(hwndMain); 
        else {
	    TranslateMessage(&msg);
	    DispatchMessage(&msg);
        }
    }
    globdat.service_thread_id = 0;
    return 0;
}


static BOOL CALLBACK console_control_handler(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
        case CTRL_BREAK_EVENT:
            fprintf(stderr, "Apache server restarting...\n");
            ap_signal_parent(SIGNAL_PARENT_RESTART);
            return TRUE;
        case CTRL_C_EVENT:
            fprintf(stderr, "Apache server interrupted...\n");
            /* for Interrupt signals, shut down the server.
             * Tell the system we have dealt with the signal
             * without waiting for Apache to terminate.
             */
            ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
            return TRUE;

        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            /* for Terminate signals, shut down the server.
             * Wait for Apache to terminate, but respond
             * after a reasonable time to tell the system
             * that we did attempt to shut ourself down.
             * THESE EVENTS WILL NOT OCCUR UNDER WIN9x!
             */
            fprintf(stderr, "Apache server shutdown initiated...\n");
            ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
            Sleep(30000);
            return TRUE;
    }
 
    /* We should never get here, but this is (mostly) harmless */
    return FALSE;
}


static void stop_console_handler(void)
{
    SetConsoleCtrlHandler(console_control_handler, FALSE);
}


void mpm_start_console_handler(void)
{
    SetConsoleCtrlHandler(console_control_handler, TRUE);
    atexit(stop_console_handler);
}


/* Special situation - children of services need to mind their
 * P's & Q's and wait quietly, ignoring the mean OS signaling
 * shutdown and other horrors, to kill them gracefully...
 */

static BOOL CALLBACK child_control_handler(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            /* for Interrupt signals, ignore them.
             * The system will also signal the parent process,
             * which will terminate Apache.
             */
            return TRUE;

        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            /* for Shutdown signals, ignore them, but...             .
             * The system will also signal the parent process,
             * which will terminate Apache, so we need to wait.
             */
            Sleep(30000);
            return TRUE;
    }
 
    /* We should never get here, but this is (mostly) harmless */
    return FALSE;
}


static void stop_child_console_handler(void)
{
    SetConsoleCtrlHandler(child_control_handler, FALSE);
}


void mpm_start_child_console_handler(void)
{
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT) {
        FreeConsole();
    }
    else
    {
        SetConsoleCtrlHandler(child_control_handler, TRUE);
        atexit(stop_child_console_handler);
    }
}


/**********************************
  WinNT service control management
 **********************************/

static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint)
{
    static int checkPoint = 1;
    int rv = APR_SUCCESS;
    
    if (globdat.hServiceStatus)
    {
        if (currentState == SERVICE_RUNNING)
            globdat.ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        else
	    globdat.ssStatus.dwControlsAccepted = 0;
        
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
    return(rv);
}

/* Set the service description regardless of platform.
 * We revert to set_service_description on NT/9x, the
 * very long way so any Apache management program can grab the
 * description.  This would be bad on Win2000, since it wouldn't
 * notify the service control manager of the name change.
 */

/* ChangeServiceConfig2() prototype:
 */
typedef WINADVAPI BOOL (WINAPI *CSD_T)(SC_HANDLE, DWORD, LPCVOID);

/* Windows 2000 alone supports ChangeServiceConfig2 in order to
 * register our server_version string... so we need some fixups
 * to avoid binding to that function if we are on WinNT/9x.
 */
static void set_service_description(void)
{
    const char *full_description;
    SC_HANDLE schSCManager;
    CSD_T ChangeServiceDescription = NULL;
    HANDLE hwin2000scm;
    BOOL ret = 0;

    /* Nothing to do if we are a console
     */
    if (!mpm_service_name)
        return;

    /* Time to fix up the description, upon each successful restart
     */
    full_description = ap_get_server_version();

    if ((osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
     && (hwin2000scm = GetModuleHandle("ADVAPI32.DLL"))
     && (ChangeServiceDescription = (CSD_T) GetProcAddress(hwin2000scm, 
                                                "ChangeServiceConfig2A"))
     && (schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)))
    {    
        SC_HANDLE schService = OpenService(schSCManager, mpm_service_name,
                                               SERVICE_ALL_ACCESS);
        if (schService) {
            if (ChangeServiceDescription(schService,
                                         1 /* SERVICE_CONFIG_DESCRIPTION */,
                                         &full_description))
                full_description = NULL;
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }

    if (full_description) 
    {
        char szPath[MAX_PATH];
        HKEY hkey;

        /* Create/Find the Service key that Monitor Applications iterate */
        apr_snprintf(szPath, sizeof(szPath), 
                     "SYSTEM\\CurrentControlSet\\Services\\%s", 
                     mpm_service_name);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szPath, 0, KEY_SET_VALUE, &hkey) 
                != ERROR_SUCCESS) {
            return;
        }

        /* Attempt to set the Description value for our service */
        RegSetValueEx(hkey, "Description", 0, REG_SZ,  
                      (unsigned char *) full_description, 
                      strlen(full_description) + 1);
        RegCloseKey(hkey);
    }
}

/* handle the SCM's ControlService() callbacks to our service */

static VOID WINAPI service_nt_ctrl(DWORD dwCtrlCode)
{
    if (dwCtrlCode == SERVICE_CONTROL_STOP)
    {
        ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
        globdat.ssStatus.dwCurrentState = SERVICE_STOP_PENDING;
        ReportStatusToSCMgr(SERVICE_STOP_PENDING, NO_ERROR, 3000);
        return;
    }
    if (dwCtrlCode == SERVICE_APACHE_RESTART)
    {
        ap_signal_parent(SIGNAL_PARENT_RESTART);
        globdat.ssStatus.dwCurrentState = SERVICE_START_PENDING;
        ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000);
        return;
    }
    
    ReportStatusToSCMgr(globdat.ssStatus.dwCurrentState, NO_ERROR, 0);            
}


long __stdcall service_stderr_thread(LPVOID hPipe)
{
    HANDLE hPipeRead = (HANDLE) hPipe;
    HANDLE hEventSource;
    char errbuf[256];
    char *errmsg = errbuf;
    const char *errarg[9];
    DWORD errlen = 0;
    DWORD errres;
    HKEY hk;
    
    errarg[0] = "The Apache service named";
    errarg[1] = mpm_display_name;
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

    CloseHandle(hPipeRead);
    return 0;
}


/* service_nt_main_fn is outside of the call stack and outside of the
 * primary server thread... so now we _really_ need a placeholder!
 * The winnt_rewrite_args has created and shared mpm_new_argv with us.
 */
extern apr_array_header_t *mpm_new_argv;

static void __stdcall service_nt_main_fn(DWORD argc, LPTSTR *argv)
{
    HANDLE waitfor[2];
    HANDLE hCurrentProcess;
    HANDLE hPipeRead = NULL;
    HANDLE hPipeWrite = NULL;
    HANDLE hPipeReadDup;
    HANDLE thread;
    DWORD  threadid;
    SECURITY_ATTRIBUTES sa = {0};  
    const char *ignored;

    /* args and service names live in the same pool */
    mpm_service_set_name(mpm_new_argv->pool, &ignored, argv[0]);

    globdat.ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    globdat.ssStatus.dwCurrentState = SERVICE_START_PENDING;
    globdat.ssStatus.dwServiceSpecificExitCode = 0;
    globdat.ssStatus.dwCheckPoint = 1;

    if (!(globdat.hServiceStatus = RegisterServiceCtrlHandler(argv[0], service_nt_ctrl)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), 
                     NULL, "Failure registering service handler");
        PulseEvent(globdat.signal_monitor);
        return;
    }

    ReportStatusToSCMgr(globdat.ssStatus.dwCurrentState, // service state
                        NO_ERROR,              // exit code
                        3000);                 // wait hint, 3 seconds more
    
    /* Create a pipe to send stderr messages to the system error log */
    hCurrentProcess = GetCurrentProcess();
    if (CreatePipe(&hPipeRead, &hPipeWrite, &sa, 0)) 
    {
        if (DuplicateHandle(hCurrentProcess, hPipeRead, hCurrentProcess,
                            &hPipeReadDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            CloseHandle(hPipeRead);
            hPipeRead = hPipeReadDup;
            thread = CreateThread(NULL, 0, service_stderr_thread, 
                                  (LPVOID) hPipeRead, 0, &threadid);
            if (thread)
            {
                int fh;
                FILE *fl;
                CloseHandle(thread);
            	fflush(stderr);
		SetStdHandle(STD_ERROR_HANDLE, hPipeWrite);
				
                fh = _open_osfhandle((long) STD_ERROR_HANDLE, 
                                     _O_WRONLY | _O_BINARY);
                dup2(fh, STDERR_FILENO);
                fl = _fdopen(STDERR_FILENO, "wcb");
                memcpy(stderr, fl, sizeof(FILE));
            }
            else
            {
                CloseHandle(hPipeRead);
                CloseHandle(hPipeWrite);
                hPipeWrite = NULL;
            }            
        }
        else
        {
            CloseHandle(hPipeRead);
            CloseHandle(hPipeWrite);
            hPipeWrite = NULL;
        }            
    }

    /* We need to append all the command arguments passed via StartService() 
     * to our running service... which just got here via the SCM...
     * but we hvae no interest in argv[0] for the mpm_new_argv list.
     */
    if (argc > 1) 
    {
        char **cmb_data;

        mpm_new_argv->nalloc = mpm_new_argv->nelts + argc - 1;
        cmb_data = apr_palloc(mpm_new_argv->pool,
                              mpm_new_argv->nalloc * sizeof(const char *));

        /* mpm_new_argv remains first (of lower significance) */
        memcpy (cmb_data, mpm_new_argv->elts, 
                mpm_new_argv->elt_size * mpm_new_argv->nelts);
        
        /* Service args follow from StartService() invocation */
        memcpy (cmb_data + mpm_new_argv->nelts, argv + 1, 
                mpm_new_argv->elt_size * (argc - 1));
        
        /* The replacement arg list is complete */
        mpm_new_argv->elts = (char *)cmb_data;
        mpm_new_argv->nelts = mpm_new_argv->nalloc;
    }
        
    /* Let the main thread continue now... but hang on to the
     * signal_monitor event so we can take further action
     */
    SetEvent(globdat.signal_monitor);

    waitfor[0] = globdat.signal_monitor;
    waitfor[1] = globdat.mpm_thread;
    WaitForMultipleObjects(2, waitfor, FALSE, INFINITE);
    /* The process is ready to terminate, or already has */

    CloseHandle(hPipeWrite);
}


DWORD WINAPI service_nt_dispatch_thread(LPVOID nada)
{
    apr_status_t rv = APR_SUCCESS;

    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "", service_nt_main_fn },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(dispatchTable))
    {
        /* This is a genuine failure of the SCM. */
        rv = apr_get_os_error();
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                     "Error starting service control dispatcher");
    }

    globdat.service_thread_id = 0;
    return (rv);
}


apr_status_t mpm_service_set_name(apr_pool_t *p, const char **display_name, 
                                  const char *set_name)
{
    char *key_name;
    apr_status_t rv;

    /* ### Needs improvement, on Win2K the user can _easily_ 
     * change the display name to a string that doesn't reflect 
     * the internal service name + whitespace!
     */
    mpm_service_name = apr_palloc(p, strlen(set_name) + 1);
    apr_collapse_spaces((char*) mpm_service_name, set_name);
    key_name = apr_psprintf(p, SERVICECONFIG, mpm_service_name);
    rv = ap_registry_get_value(p, key_name, "DisplayName", &mpm_display_name);
    if (rv != APR_SUCCESS) {
        /* Take the given literal name if there is no service entry */
        mpm_display_name = apr_pstrdup(p, set_name);
    }
    *display_name = mpm_display_name;
    return rv;
}


apr_status_t mpm_merge_service_args(apr_pool_t *p, 
                                   apr_array_header_t *args, 
                                   int fixed_args)
{
    apr_array_header_t *svc_args = NULL;
    char conf_key[MAX_PATH];
    char **cmb_data;
    apr_status_t rv;

    apr_snprintf(conf_key, sizeof(conf_key), SERVICEPARAMS, mpm_service_name);
    rv = ap_registry_get_array(p, conf_key, "ConfigArgs", &svc_args);
    if (rv != APR_SUCCESS) {
        if (rv == ERROR_FILE_NOT_FOUND) {
            ap_log_error(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, NULL,
                         "No ConfigArgs registered for %s, perhaps "
                         "this service is not installed?", 
                         mpm_service_name);
            return APR_SUCCESS;
        }
        else
            return (rv);        
    }

    if (!svc_args || svc_args->nelts == 0) {
        return (APR_SUCCESS);
    }

    /* Now we have the mpm_service_name arg, and the mpm_runservice_nt()
     * call appended the arguments passed by StartService(), so it's  
     * time to _prepend_ the default arguments for the server from 
     * the service's default arguments (all others override them)...
     */
    args->nalloc = args->nelts + svc_args->nelts;
    cmb_data = apr_palloc(p, args->nalloc * sizeof(const char *));

    /* First three args (argv[0], -f, path) remain first */
    memcpy(cmb_data, args->elts, args->elt_size * fixed_args);
    
    /* Service args follow from service registry array */
    memcpy(cmb_data + fixed_args, svc_args->elts, 
           svc_args->elt_size * svc_args->nelts);
    
    /* Remaining new args follow  */
    memcpy(cmb_data + fixed_args + svc_args->nelts,
           (const char **)args->elts + fixed_args, 
           args->elt_size * (args->nelts - fixed_args));
    
    args->elts = (char *)cmb_data;
    args->nelts = args->nalloc;

    return APR_SUCCESS;
}


void service_stopped(void)
{
    /* Still have a thread & window to clean up, so signal now */
    if (globdat.service_thread_id)
    {
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
        {
            ReportStatusToSCMgr(SERVICE_STOPPED,    // service state
                                NO_ERROR,           // exit code
                                0);                 // wait hint

            /* Cause the service_nt_main_fn to complete */
            SetEvent(globdat.signal_monitor);
        }
        else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
        {
            RegisterServiceProcess(0, 0);
            PostThreadMessage(globdat.service_thread_id, WM_CLOSE, 0, 0);
        }

        WaitForSingleObject(globdat.service_thread, 5000);
        CloseHandle(globdat.service_thread);
    }
}


apr_status_t mpm_service_to_start(const char **display_name)
{
    HANDLE waitfor[2];

    globdat.mpm_thread = GetCurrentThread();
    
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        globdat.signal_monitor = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (globdat.signal_monitor)
            globdat.service_thread = CreateThread(NULL, 0, 
                                                  service_nt_dispatch_thread, 
                                                  NULL, 0, 
                                                  &globdat.service_thread_id);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        if (!RegisterServiceProcess(0, 1)) 
            return GetLastError();

        globdat.signal_monitor = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (globdat.signal_monitor)
            globdat.service_thread = CreateThread(NULL, 0,
                                                  monitor_service_9x_thread, 
                                                  (LPVOID) mpm_service_name, 0, 
                                                  &globdat.service_thread_id);
    }

    if (globdat.signal_monitor && globdat.service_thread) 
    {
        waitfor[0] = globdat.signal_monitor;
        waitfor[1] = globdat.service_thread;
    
        /* SetEvent(globdat.signal_monitor) to clean up the SCM thread */
        if (WaitForMultipleObjects(2, waitfor, FALSE, 10000) != WAIT_OBJECT_0) {
            CloseHandle(globdat.service_thread);
            return APR_ENOTHREAD;
        }
    }

    if (globdat.service_thread_id)
        atexit(service_stopped);
    else if (globdat.service_thread)
        CloseHandle(globdat.service_thread);

    *display_name = mpm_display_name; 
    return APR_SUCCESS;
}


apr_status_t mpm_service_started(void)
{
    set_service_description();
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        ReportStatusToSCMgr(SERVICE_RUNNING,    // service state
                            NO_ERROR,           // exit code
                            0);                 // wait hint
    }
    return APR_SUCCESS;
}


void mpm_service_stopping(void)
{
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
        ReportStatusToSCMgr(SERVICE_STOP_PENDING, // service state
                            NO_ERROR,             // exit code
                            3000);                // wait hint
}


apr_status_t mpm_service_install(apr_pool_t *ptemp, int argc, 
                                 const char * const * argv)
{
    char key_name[MAX_PATH];
    char exe_path[MAX_PATH];
    char *launch_cmd;
    apr_status_t(rv);
    
    printf("Installing the %s service\n", mpm_display_name);

    if (GetModuleFileName(NULL, exe_path, sizeof(exe_path)) == 0)
    {
        apr_status_t rv = apr_get_os_error();
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                     "GetModuleFileName failed");
        return rv;
    }

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        SC_HANDLE   schService;
        SC_HANDLE   schSCManager;
    
        // TODO: Determine the minimum permissions required for security
        schSCManager = OpenSCManager(NULL, NULL, /* local, default database */
                                     SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "Failed to open the WinNT service manager");
            return (rv);
        }

        launch_cmd = apr_psprintf(ptemp, "\"%s\" -k runservice", exe_path);

        /* RPCSS is the Remote Procedure Call (RPC) Locator required for DCOM 
         * communication pipes.  I am far from convinced we should add this to
         * the default service dependencies, but be warned that future apache 
         * modules or ISAPI dll's may depend on it.
         */
        schService = CreateService(schSCManager,         // SCManager database
                                   mpm_service_name,     // name of service
                                   mpm_display_name,     // name to display
                                   SERVICE_ALL_ACCESS,   // access required
                                   SERVICE_WIN32_OWN_PROCESS,  // service type
                                   SERVICE_AUTO_START,   // start type
                                   SERVICE_ERROR_NORMAL, // error control type
                                   launch_cmd,           // service's binary
                                   NULL,                 // no load svc group
                                   NULL,                 // no tag identifier
                                   "Tcpip\0Afd\0",       // dependencies
                                   NULL,                 // use SYSTEM account
                                   NULL);                // no password

        if (!schService) 
        {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL, 
                         "Failed to create WinNT Service Profile");
            CloseServiceHandle(schSCManager);
            return (rv);
        }

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        /* Store the launch command in the registry */
        launch_cmd = apr_psprintf(ptemp, "\"%s\" -n %s -k runservice", 
                                 exe_path, mpm_service_name);
        rv = ap_registry_store_value(SERVICECONFIG9X, mpm_service_name, launch_cmd);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL, 
                         "%s: Failed to add the RunServices registry entry.", 
                         mpm_display_name);
            return (rv);
        }

        apr_snprintf(key_name, sizeof(key_name), SERVICECONFIG, mpm_service_name);
        rv = ap_registry_store_value(key_name, "ImagePath", launch_cmd);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL, 
                         "%s: Failed to store ImagePath in the registry.", 
                         mpm_display_name);
            return (rv);
        }
        rv = ap_registry_store_value(key_name, "DisplayName", mpm_display_name);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL, 
                         "%s: Failed to store DisplayName in the registry.", 
                         mpm_display_name);
            return (rv);
        }
    }

    set_service_description();

    /* For both WinNT & Win9x store the service ConfigArgs in the registry...
     */
    apr_snprintf(key_name, sizeof(key_name), SERVICEPARAMS, mpm_service_name);
    rv = ap_registry_store_array(ptemp, key_name, "ConfigArgs", argc, argv);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL, 
                     "%s: Failed to store the ConfigArgs in the registry.", 
                     mpm_display_name);
        return (rv);
    }
    printf("The %s service is successfully installed.\n", mpm_display_name);
    return APR_SUCCESS;
}


apr_status_t mpm_service_uninstall(void)
{
    char key_name[MAX_PATH];
    apr_status_t rv;

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        SC_HANDLE schService;
        SC_HANDLE schSCManager;

        printf("Removing the %s service\n", mpm_display_name);

        // TODO: Determine the minimum permissions required for security
        schSCManager = OpenSCManager(NULL, NULL, /* local, default database */
                                     SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "Failed to open the WinNT service manager.");
            return (rv);
        }
        
        schService = OpenService(schSCManager, mpm_service_name, SERVICE_ALL_ACCESS);

        if (!schService) {
           rv = apr_get_os_error();
           ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
			"%s: OpenService failed", mpm_display_name);
           return (rv);
        }
        
        /* assure the service is stopped before continuing
         *
         * This may be out of order... we might not be able to be
         * granted all access if the service is running anyway.
         *
         * And do we want to make it *this easy* for them
         * to uninstall their service unintentionally?
         */
        // ap_stop_service(schService);

        if (DeleteService(schService) == 0) {
            rv = apr_get_os_error();
	    ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "%s: Failed to delete the service.", mpm_display_name);
            return (rv);
        }
        
        CloseServiceHandle(schService);        
        CloseServiceHandle(schSCManager);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        printf("Removing the %s service\n", mpm_display_name);

        /* TODO: assure the service is stopped before continuing */

        if (ap_registry_delete_value(SERVICECONFIG9X, mpm_service_name)) {
            rv = apr_get_os_error();
	    ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "%s: Failed to remove the RunServices registry "
                         "entry.", mpm_display_name);
            return (rv);
        }
        
        /* we blast Services/us, not just the Services/us/Parameters branch */
        apr_snprintf(key_name, sizeof(key_name), SERVICECONFIG, mpm_service_name);
        if (ap_registry_delete_key(key_name)) 
        {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "%s: Failed to remove the service config from the "
                         "registry.", mpm_display_name);
            return (rv);
        }
    }
    printf("The %s service has been removed successfully.\n", mpm_display_name);
    return APR_SUCCESS;
}


/* signal_service_transition is a simple thunk to signal the service
 * and monitor its successful transition.  If the signal passed is 0,
 * then the caller is assumed to already have performed some service 
 * operation to be monitored (such as StartService), and no actual
 * ControlService signal is sent.
 */

static int signal_service_transition(SC_HANDLE schService, DWORD signal, DWORD pending, DWORD complete)
{
    if (signal && !ControlService(schService, signal, &globdat.ssStatus)) 
        return FALSE;
    
    do {
        Sleep(1000);    
        if (!QueryServiceStatus(schService, &globdat.ssStatus))
            return FALSE;
    } while (globdat.ssStatus.dwCurrentState == pending);
        
    return (globdat.ssStatus.dwCurrentState == complete);
}


apr_status_t mpm_service_start(apr_pool_t *ptemp, int argc, 
                               const char * const * argv)
{
    apr_status_t rv;
    
    printf("Starting the %s service\n", mpm_display_name);

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        char **start_argv;
        SC_HANDLE   schService;
        SC_HANDLE   schSCManager;

        // TODO: Determine the minimum permissions required for security
        schSCManager = OpenSCManager(NULL, NULL, /* local, default database */
                                     SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "Failed to open the WinNT service manager");
            return (rv);
        }

        schService = OpenService(schSCManager, mpm_service_name, 
                                 SERVICE_START | SERVICE_QUERY_STATUS);
        if (!schService) {
            rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "%s: Failed to open the service.", mpm_display_name);
            CloseServiceHandle(schSCManager);
            return (rv);
        }

        if (QueryServiceStatus(schService, &globdat.ssStatus)
            && (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING)) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, 0, NULL,
                         "Service %s is already started!", mpm_display_name);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return 0;
        }
        
        argc += 1;
        start_argv = apr_palloc(ptemp, argc * sizeof(const char **));
        start_argv[0] = mpm_service_name;
        if (argc > 1)
            memcpy(start_argv + 1, argv, (argc - 1) * sizeof(const char **));
        
        rv = APR_EINIT;
        if (StartService(schService, argc, start_argv)
            && signal_service_transition(schService, 0, /* test only */
                                         SERVICE_START_PENDING, 
                                         SERVICE_RUNNING))
                rv = APR_SUCCESS;

        if (rv != APR_SUCCESS)
            rv = apr_get_os_error();
        
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        STARTUPINFO si;           /* Filled in prior to call to CreateProcess */
        PROCESS_INFORMATION pi;   /* filled in on call to CreateProcess */
        char exe_path[MAX_PATH];
        char *pCommand;
        int i;

        /* Locate the active top level window named service_name
         * provided the class is ApacheWin95ServiceMonitor
         */
        if (FindWindow("ApacheWin95ServiceMonitor", mpm_service_name)) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, 0, NULL,
                         "Service %s is already started!", mpm_display_name);
            return 0;
        }

        /* This may not appear intuitive, but Win9x will not allow a process
         * to detach from the console without releasing the entire console.
         * Ergo, we must spawn a new process for the service to get back our
         * console window.
         * The config is pre-flighted, so there should be no danger of failure.
         */
        
        if (GetModuleFileName(NULL, exe_path, sizeof(exe_path)) == 0)
        {
            apr_status_t rv = apr_get_os_error();
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, rv, NULL,
                         "GetModuleFileName failed");
            return rv;
        }
        
        pCommand = apr_psprintf(ptemp, "\"%s\" -n %s -k runservice", 
                               exe_path, mpm_service_name);  
        for (i = 0; i < argc; ++i) {
            pCommand = apr_pstrcat(ptemp, pCommand,
                                   " \"", argv[i], "\"", NULL);
        }
        
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags     = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;   /* This might be redundant */
        
        rv = APR_EINIT;
        if (CreateProcess(NULL, pCommand, NULL, NULL, FALSE, 
                           DETACHED_PROCESS, /* Creation flags */
                           NULL, NULL, &si, &pi)) 
        {
            DWORD code;
            while (GetExitCodeProcess(pi.hProcess, &code) == STILL_ACTIVE) {
                if (FindWindow("ApacheWin95ServiceMonitor", mpm_service_name)) {
                    rv = APR_SUCCESS;
                    break;
                }
                Sleep (1000);
            }
        }
        
        if (rv != APR_SUCCESS)
            rv = apr_get_os_error();
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }    

    if (rv == APR_SUCCESS)
        printf("The %s service is running.\n", mpm_display_name);
    else
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                     "%s: Failed to start the service process.",
                     mpm_display_name);
        
    return rv;
}


/* signal is zero to stop, non-zero for restart */

void mpm_signal_service(apr_pool_t *ptemp, int signal)
{
    int success = FALSE;
    
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT) 
    {
        SC_HANDLE   schService;
        SC_HANDLE   schSCManager;

        schSCManager = OpenSCManager(NULL, NULL, // default machine & database
                                     SC_MANAGER_ALL_ACCESS);
        
        if (!schSCManager) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), NULL,
                         "Failed to open the NT Service Manager");
            return;
        }
        
        schService = OpenService(schSCManager, mpm_service_name, 
                                 SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), NULL,
                         "Failed to open the %s Service", mpm_display_name);
            CloseServiceHandle(schSCManager);
            return;
        }
        
        if (!QueryServiceStatus(schService, &globdat.ssStatus)) {
            ap_log_error(APLOG_MARK, APLOG_ERR | APLOG_STARTUP, apr_get_os_error(), NULL,
                         "Query of Service %s failed", mpm_display_name);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return;
        }

        if (!signal && (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED)) {
            printf("The %s service is not started.\n", mpm_display_name);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return;
        }
        
        printf("The %s service is %s.\n", mpm_display_name, 
               signal ? "restarting" : "stopping");

        if (!signal)
            success = signal_service_transition(schService, 
                                                SERVICE_CONTROL_STOP, 
                                                SERVICE_STOP_PENDING, 
                                                SERVICE_STOPPED);
        else if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED) {
            mpm_service_start(ptemp, 0, NULL);
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return;
        }
        else
            success = signal_service_transition(schService, 
                                                SERVICE_APACHE_RESTART, 
                                                SERVICE_START_PENDING, 
                                                SERVICE_RUNNING);

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
    }
    else /* !isWindowsNT() */
    {
        DWORD       service_pid;
        HANDLE      hwnd;
        char prefix[20];
        /* Locate the active top level window named service_name
         * provided the class is ApacheWin95ServiceMonitor
         */
        hwnd = FindWindow("ApacheWin95ServiceMonitor", mpm_service_name);
        if (hwnd && GetWindowThreadProcessId(hwnd, &service_pid))
            globdat.ssStatus.dwCurrentState = SERVICE_RUNNING;
        else
        {
            globdat.ssStatus.dwCurrentState = SERVICE_STOPPED;
            if (!signal) {
                printf("The %s service is not started.\n", mpm_display_name);
                return;
            }
        }

        printf("The %s service is %s.\n", mpm_display_name, 
               signal ? "restarting" : "stopping");

        apr_snprintf(prefix, sizeof(prefix), "ap%ld", (long)service_pid);
        setup_signal_names(prefix);

        if (!signal) 
        {
            int ticks = 60;
            ap_signal_parent(SIGNAL_PARENT_SHUTDOWN);
            while (--ticks)
            {
                if (!IsWindow(hwnd)) {
                    success = TRUE;
                    break;
                }
                Sleep(1000);
            }
        }
        else /* !stop */
        {   
            /* TODO: Aught to add a little test to the restart logic, and
             * store the restart counter in the window's user dword.
             * Then we can hang on and report a successful restart.  But
             * that's a project for another day.
             */
            if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED) {
                mpm_service_start(ptemp, 0, NULL);
                return;
            }
            else {
                success = TRUE;
                ap_signal_parent(SIGNAL_PARENT_RESTART);
            }
        }
    }

    if (success)
        printf("The %s service has %s.\n", mpm_display_name, 
               signal ? "restarted" : "stopped");
    else
        printf("Failed to %s the %s service.\n", 
               signal ? "restart" : "stop", mpm_display_name);
}
