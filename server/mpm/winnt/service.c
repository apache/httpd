/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif
#ifndef NOGDI
#define NOGDI
#endif
#ifndef NONLS
#define NONLS
#endif
#ifndef NOMCX
#define NOMCX
#endif
#ifndef NOIME
#define NOIME
#endif
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>

#define  CORE_PRIVATE 

#include "httpd.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "winnt.h"

char *service_name = NULL;
char *display_name = NULL;
char *signal_arg = NULL;
    
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
 *     \ImagePath            (NT Only)
 *     \Parameters\ConfigArgs
 *
 * For Win9x, the launch service command is stored under:
 *
 * HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices\[service name]
 */


static LRESULT CALLBACK monitor_service_9x_proc(HWND hWnd, UINT msg, 
                                                WPARAM wParam, LPARAM lParam)
{
/* This is the WndProc procedure for our invisible window.
 * When the user shuts down the system, this window is sent
 * a signal WM_ENDSESSION. We clean up by signaling Apache
 * to shut down, and idle until Apache's primary thread quits.
 */
    if ((msg == WM_ENDSESSION) && (lParam != ENDSESSION_LOGOFF))
    {
        signal_parent(0);
	if (wParam)
            /* Don't leave this message until we are dead! */
	    WaitForSingleObject(globdat.mpm_thread, 30000);
        return 0;
    }
    return (DefWindowProc(hWnd, msg, wParam, lParam));
}

static DWORD WINAPI monitor_service_9x_thread(LPVOID initEvent)
{
/* When running on Windows 9x, the ConsoleCtrlHandler is _NOT_ 
 * called when the system is shutdown.  So create an invisible 
 * window to watch for the WM_ENDSESSION message, and watch for
 * the WM_CLOSE message to shut the window down.
 */
    WNDCLASS wc;
    HWND hwndMain;

    wc.style         = CS_GLOBALCLASS;
    wc.lpfnWndProc   = monitor_service_9x_proc; 
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0; 
    wc.hInstance     = NULL;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = "ApacheWin9xServiceMonitor";
 
    if (RegisterClass(&wc)) 
    {
        /* Create an invisible window */
        hwndMain = CreateWindow(wc.lpszClassName, display_name, 
 	                        WS_OVERLAPPEDWINDOW & ~WS_VISIBLE, 
                                CW_USEDEFAULT, CW_USEDEFAULT, 
                                CW_USEDEFAULT, CW_USEDEFAULT, 
                                NULL, NULL, NULL, NULL);
        if (hwndMain)
        {
            MSG msg;
            /* If we succeed, eliminate the console window.
             * Signal the parent we are all set up, and
             * watch the message queue while the window lives.
             */
            FreeConsole();
            SetEvent((HANDLE) initEvent);
            while (GetMessage(&msg, NULL, 0, 0)) 
            {
                if (msg.message == WM_CLOSE)
                    DestroyWindow(hwndMain); 
                else {
	            TranslateMessage(&msg);
	            DispatchMessage(&msg);
                }
            }
            globdat.service_thread = 0;
            return(0);
        }
    }
    /* We failed or are soon to die... 
     * we won't need this much longer 
     */
    SetEvent(globdat.signal_monitor);
    globdat.service_thread = 0;
    return(0);
}

void service_9x_stopped(void)
{
    /* Still have a thread & window to clean up, so signal now */
    if (globdat.service_thread)
    {
        PostThreadMessage(globdat.service_thread_id, WM_CLOSE, 0, 0);
        // TODO: Test Possible (30 second) deadlock if we are shutting down
        WaitForSingleObject(globdat.service_thread, 30000);
    }

    /* When the service quits, remove it from the 
       system service table */
    RegisterServiceProcess(0, 0);

    return;
}

static BOOL CALLBACK console_control_handler(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            fprintf(stderr, "Apache server interrupted...\n");
            /* for Interrupt signals, shut down the server.
             * Tell the system we have dealt with the signal
             * without waiting for Apache to terminate.
             */
            signal_parent(0);
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
            signal_parent(0);
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

// TODO: We really need to play the RegisterServiceProcess game 
//       if this is the child of the Win9x service process...
//       and if that isn't bad enought... a shutdown thread window
//       is really the ticket...  ick.

static void stop_child_console_handler(void)
{
    SetConsoleCtrlHandler(child_control_handler, FALSE);
}

void mpm_start_child_console_handler(void)
{
    SetConsoleCtrlHandler(child_control_handler, TRUE);
    atexit(stop_child_console_handler);
}


/**********************************
  WinNT service control management
 **********************************/

static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint)
{
    static int checkPoint = 1;
    int rv = APR_SUCCESS;
    
    if(globdat.hServiceStatus)
    {
        if (currentState == SERVICE_RUNNING)
            globdat.ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        else
	    globdat.ssStatus.dwControlsAccepted = 0;
        
        globdat.ssStatus.dwCurrentState = currentState;
        globdat.ssStatus.dwWin32ExitCode = exitCode;
        if(waitHint)
            globdat.ssStatus.dwWaitHint = waitHint;

        if ( ( currentState == SERVICE_RUNNING ) ||
             ( currentState == SERVICE_STOPPED ) )
        {
            globdat.ssStatus.dwWaitHint = 0;
            globdat.ssStatus.dwCheckPoint = 0;
        }
        else
            globdat.ssStatus.dwCheckPoint = ++checkPoint;

        rv = SetServiceStatus(globdat.hServiceStatus, &globdat.ssStatus);

    }
    return(rv);
}

/* handle the SCM's ControlService() callbacks to our service */

static VOID WINAPI service_nt_ctrl(DWORD dwCtrlCode)
{
    if (dwCtrlCode == SERVICE_CONTROL_STOP)
        /* Reports our status change itself */
        signal_parent(0);
    
    ReportStatusToSCMgr(globdat.ssStatus.dwCurrentState, NO_ERROR, 0);            
}

/* service_nt_main_fn is outside of the call stack and outside of the
 * primary server thread... so now we _really_ need a placeholder!
 * The winnt_rewrite_args has created and shared mpm_new_argv with us.
 */
extern ap_array_header_t *mpm_new_argv;

static void __stdcall service_nt_main_fn(DWORD argc, LPTSTR *argv)
{
    /* args and service names live in the same pool */
    mpm_service_set_name(mpm_new_argv->cont, argv[0]);

    globdat.ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    globdat.ssStatus.dwCurrentState = SERVICE_START_PENDING;
    globdat.ssStatus.dwServiceSpecificExitCode = 0;
    globdat.ssStatus.dwCheckPoint = 1;

    if(!(globdat.hServiceStatus = RegisterServiceCtrlHandler(argv[0], service_nt_ctrl)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
        "Failure registering service handler");
        return;
    }

    ReportStatusToSCMgr(globdat.ssStatus.dwCurrentState, // service state
                        NO_ERROR,              // exit code
                        3000);                 // wait hint, 3 seconds more
    
    /* We need to append all the command arguments passed via StartService() 
     * to our running service... which just got here via the SCM...
     * but we hvae no interest in argv[0] for the mpm_new_argv list.
     */
    if (argc > 1) 
    {
        char **cmb_data;
        cmb_data = ap_palloc(mpm_new_argv->cont, 
                             (mpm_new_argv->nelts + argc - 1) * sizeof(char *));

        /* mpm_new_argv remains first (of lower significance) */
        memcpy (cmb_data, mpm_new_argv->elts, 
                mpm_new_argv->elt_size * mpm_new_argv->nelts);
        
        /* Service args follow from StartService() invocation */
        memcpy (cmb_data + mpm_new_argv->nelts, argv + 1, 
                mpm_new_argv->elt_size * (argc - 1));
        
        /* The replacement arg list is complete */
        mpm_new_argv->elts = (char*) cmb_data;
        mpm_new_argv->nalloc = mpm_new_argv->nelts += argc - 1;
    }
        
    /* Let the main thread continue now... but hang on to the
     * signal_monitor event so we can take further action
     */
    PulseEvent(globdat.signal_monitor);

    // TODO: Wait on mpm_thread as well!!!
    //       Hey, we could even add a timeout during startup
    //       to tickle the SCM every second or few till we finish.
    WaitForSingleObject(globdat.signal_monitor, INFINITE);
    
    /* This function only returns when we are killed */
}

DWORD WINAPI service_nt_dispatch_thread(LPVOID nada)
{
    ap_status_t rv = APR_SUCCESS;

    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "", service_nt_main_fn },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(dispatchTable))
    {
        /* This is a genuine failure of the SCM. */
        rv = GetLastError();
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                     "Error starting service control dispatcher");
    };
    globdat.service_thread = 0;
    return (rv);
}

void mpm_service_nt_stopping(void)
{
    ReportStatusToSCMgr(SERVICE_STOP_PENDING, // service state
                        NO_ERROR,             // exit code
                        1000);                // wait hint
}

static void service_nt_stopped(void)
{
    ReportStatusToSCMgr(SERVICE_STOPPED,    // service state
                        NO_ERROR,           // exit code
                        0);                 // wait hint

    /* Cause the instant closure of the service_nt_main_fn */
    SetEvent(globdat.signal_monitor);
}

ap_status_t mpm_service_set_name(ap_pool_t *p, char *name)
{
    char *key_name;
    
    // TODO: the display name might have been modified in the registry...
    //       Win9x could walk for DisplayName in the services entries
    service_name = ap_palloc(p, strlen(name) + 1);
    ap_collapse_spaces(service_name, name);
    key_name = ap_psprintf(p, SERVICECONFIG, service_name);
    if (ap_registry_get_value(p, key_name, "DisplayName", &display_name) == APR_SUCCESS)
        return APR_SUCCESS;

    display_name = ap_pstrdup(p, name);
    return APR_NOTFOUND;
}

ap_status_t mpm_merge_service_args(ap_pool_t *p, 
                                   ap_array_header_t *args, 
                                   int fixed_args)
{
    ap_array_header_t *svc_args = NULL;
    char conf_key[MAX_PATH];
    char **cmb_data;
    ap_status_t rv;

    ap_snprintf(conf_key, sizeof(conf_key), SERVICEPARAMS, service_name);
    rv = ap_registry_get_array(p, conf_key, "ConfigArgs", &svc_args);
    if (rv != APR_SUCCESS) {
        // TODO: More message?
        return (rv);        
    }

    if (!svc_args || svc_args->nelts == 0) {
        return (APR_SUCCESS);
    }

    /* Now we have the service_name arg, and the mpm_runservice_nt()
     * call appended the arguments passed by StartService(), so it's  
     * time to _prepend_ the default arguments for the server from 
     * the service's default arguments (all others override them)...
     */
    cmb_data = ap_palloc(p, (args->nelts + svc_args->nelts) * sizeof(char *));

    /* First three args (argv[0], -f, path) remain first */
    memcpy (cmb_data, args->elts, args->elt_size * fixed_args);
    
    /* Service args follow from service registry array */
    memcpy (cmb_data + fixed_args, svc_args->elts, 
            svc_args->elt_size * svc_args->nelts);
    
    /* Remaining new args follow  */
    memcpy (cmb_data + fixed_args + svc_args->nelts,
            (char**) args->elts + fixed_args, 
            args->elt_size * (args->nelts - fixed_args));
    
    args->elts = (char*) cmb_data;
    args->nalloc = (args->nelts += svc_args->nelts);

    return APR_SUCCESS;
}

ap_status_t mpm_service_to_start(void)
{
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        globdat.signal_monitor = CreateEvent(NULL, FALSE, FALSE, NULL);
        globdat.service_thread = CreateThread(NULL, 0, 
                                              service_nt_dispatch_thread, 
                                              NULL, 0, 
                                              &globdat.service_thread_id);
    
        // TODO: Add service_thread to this wait as well
        WaitForSingleObject(globdat.signal_monitor, 45000);

        if (!globdat.service_thread)
            return APR_ENOTHREAD;

        /* SetEvent(globdat.signal_monitor) to clean up the SCM thread */
        atexit(service_nt_stopped);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        globdat.mpm_thread = GetCurrentThread();
    
        if (RegisterServiceProcess(0, 1)) {
            globdat.signal_monitor = CreateEvent(NULL, FALSE, FALSE, NULL);
            globdat.service_thread = CreateThread(NULL, 0,
                                                  monitor_service_9x_thread, 
                                                  NULL, 0, 
                                                  &globdat.service_thread_id);
            // TODO: Add service_thread to the wait as well.
            WaitForSingleObject(globdat.signal_monitor, 30000);
        }

        if (!globdat.service_thread)
            return APR_ENOTHREAD;

        /* PostThreadMessage to clean up the hidden monitor window */
        atexit(service_9x_stopped);
    }
    return APR_SUCCESS;
}

ap_status_t mpm_service_started(void)
{
    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        ReportStatusToSCMgr(SERVICE_RUNNING,    // service state
                            NO_ERROR,           // exit code
                            0);                 // wait hint
    }
    return APR_SUCCESS;
}

ap_status_t mpm_service_install(ap_pool_t *ptemp, int argc, 
                                char const* const* argv)
{
    char key_name[MAX_PATH];
    char exe_path[MAX_PATH];
    char *launch_cmd;
    ap_status_t(rv);
    
    printf("Installing the %s service\n", display_name);

    if (GetModuleFileName(NULL, exe_path, sizeof(exe_path)) == 0)
    {
        ap_status_t rv = GetLastError();
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
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
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "Failed to open the WinNT service manager");
            return (rv);
        }

        launch_cmd = ap_psprintf(ptemp, "\"%s\" -k runservice", exe_path);

        /* RPCSS is the Remote Procedure Call (RPC) Locator required for DCOM 
         * communication pipes.  I am far from convinced we should add this to
         * the default service dependencies, but be warned that future apache 
         * modules or ISAPI dll's may depend on it.
         */
        schService = CreateService(schSCManager,         // SCManager database
                                   service_name,         // name of service
                                   display_name,         // name to display
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
            ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL, 
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
        launch_cmd = ap_psprintf(ptemp, "\"%s\" -n %s -k runservice", 
                                 exe_path, service_name);
        rv = ap_registry_store_value(SERVICECONFIG9X, service_name, launch_cmd);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, 
                         "%s: Failed to add the RunServices registry entry.", 
                         display_name);
            return (rv);
        }

        ap_snprintf(key_name, sizeof(key_name), SERVICECONFIG, service_name);
        rv = ap_registry_store_value(key_name, "DisplayName", display_name);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, 
                         "%s: Failed to store DisplayName in the registry.", 
                         display_name);
            return (rv);
        }
    }

    /* For both WinNT & Win9x store the service ConfigArgs in the registry...
     */
    ap_snprintf(key_name, sizeof(key_name), SERVICEPARAMS, service_name);
    rv = ap_registry_store_array(ptemp, key_name, "ConfigArgs", argc, argv);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL, 
                     "%s: Failed to store the ConfigArgs in the registry.", 
                     display_name);
        return (rv);
    }
    printf("The %s service is successfully installed.\n", display_name);
}


ap_status_t mpm_service_uninstall(void)
{
    char key_name[MAX_PATH];
    ap_status_t rv;

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        SC_HANDLE schService;
        SC_HANDLE schSCManager;

        printf("Removing the %s service\n", display_name);

        // TODO: Determine the minimum permissions required for security
        schSCManager = OpenSCManager(NULL, NULL, /* local, default database */
                                     SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "Failed to open the WinNT service manager.");
            return (rv);
        }
        
        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (!schService) {
           rv = GetLastError();
           ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
			"%s: OpenService failed", display_name);
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
            rv = GetLastError();
	    ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: Failed to delete the service.", display_name);
            return (rv);
        }
        
        CloseServiceHandle(schService);        
        CloseServiceHandle(schSCManager);
    }
    else /* osver.dwPlatformId != VER_PLATFORM_WIN32_NT */
    {
        printf("Removing the %s service\n", display_name);

        /* TODO: assure the service is stopped before continuing*/

        if (ap_registry_delete_value(SERVICECONFIG9X, service_name)) {
            rv = GetLastError();
	    ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: Failed to remove the RunServices registry "
                         "entry.", display_name);
            return (rv);
        }
        
        /* we blast Services/us, not just the Services/us/Parameters branch */
        ap_snprintf(key_name, sizeof(key_name), SERVICECONFIG, service_name);
        if (ap_registry_delete_key(key_name)) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: Failed to remove the service config from the "
                         "registry.", display_name);
            return (rv);
        }
    }
    printf("The %s service has been removed successfully.\n", display_name);
    return APR_SUCCESS;
}

ap_status_t mpm_service_start(ap_pool_t *ptemp, int argc, 
                              char const* const* argv)
{
    ap_status_t rv;
    
    printf("Starting the %s service\n", display_name);

    if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
    {
        char **start_argv;
        SC_HANDLE   schService;
        SC_HANDLE   schSCManager;

        // TODO: Determine the minimum permissions required for security
        schSCManager = OpenSCManager(NULL, NULL, /* local, default database */
                                     SC_MANAGER_ALL_ACCESS);
        if (!schSCManager) {
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "Failed to open the WinNT service manager");
            return (rv);
        }

        schService = OpenService(schSCManager, service_name, 
                                 SERVICE_START | SERVICE_QUERY_STATUS);
        if (!schService) {
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: Failed to open the service.", display_name);
            CloseServiceHandle(schSCManager);
            return (rv);
        }

        argc += 1;
        start_argv = ap_palloc(ptemp, argc * sizeof(char**));
        start_argv[0] = service_name;
        memcpy(start_argv + 1, argv, (argc - 1) * sizeof(char**));
        
        rv = APR_SUCCESS;
        if (StartService(schService, argc, start_argv))
        {
            globdat.ssStatus.dwCurrentState = SERVICE_START_PENDING;
            while(globdat.ssStatus.dwCurrentState == SERVICE_START_PENDING) {
                Sleep(1000);
                if (!QueryServiceStatus(schService, &globdat.ssStatus)) {
                    rv = GetLastError();
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                                 "%s: QueryServiceStatus failed.", 
                                 display_name);
                    break;
                }                
            }
            // TODO: Something informative, plus a time out, would be nice.
        }
        else
        {
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: StartService failed.", display_name);
        }

        if ((rv == APR_SUCCESS )
                && (globdat.ssStatus.dwCurrentState != SERVICE_RUNNING))
        {
            rv = globdat.ssStatus.dwCurrentState;
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "%s: StartService failed.", display_name);
        }

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

        /* This may not appear intuitive, but Win9x will not allow a process
         * to detach from the console without releasing the entire console.
         * Ergo, we must spawn a new process for the service to get back our
         * console window.
         * The config is pre-flighted, so there should be no danger of failure.
         */
        
        if (GetModuleFileName(NULL, exe_path, sizeof(exe_path)) == 0)
        {
            ap_status_t rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, NULL,
                         "GetModuleFileName failed");
            return rv;
        }
        
        pCommand = ap_psprintf(ptemp, "\"%s\" -n %s -k runservice", 
                               exe_path, service_name);  
        for (i = 0; i < argc; ++i) {
            pCommand = ap_pstrcat(ptemp, pCommand, " \"", argv[i], "\"", NULL);
        }
        
        memset(&si, 0, sizeof(si));
        memset(&pi, 0, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags     = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;   /* This might be redundant */

        if (!CreateProcess(NULL, pCommand, NULL, NULL, FALSE, 
                           DETACHED_PROCESS, /* Creation flags */
                           NULL, NULL, &si, &pi)) 
        {
            rv = GetLastError();
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL,
                         "%s: Failed to create the service process.",
                         display_name);
            /* Just in case... */
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return (rv);
        }

        // TODO: We can watch the pi.hProcess and wait to be able to open the
        //       shutdown Event of pi.dwProcessId... hang around for a minute
        //       or so on 1 second Sleeps, and declare failure on timeout or
        //       an invalid pi.hProcess handle.
        //       However, that isn't the biggest priority right now :-)
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }    

    if (rv != APR_SUCCESS) {
        return (rv);
    }

    printf("The %s service is running.\n", display_name);
    return APR_SUCCESS;
}

void mpm_signal_service(ap_pool_t *ptemp, char *fname, int signal)
{
    long readpid = 0;
    char pid_str[10]; /* long enough for a long */
    const char *pid_fname = ap_server_root_relative(ptemp, fname);
    ap_file_t *pid_file = NULL;
    ap_finfo_t finfo;

    if (ap_stat(&finfo, pid_fname, ptemp) == APR_SUCCESS) 
    {
        if (ap_open(&pid_file, pid_fname, APR_READ,
                APR_OS_DEFAULT, ptemp) == APR_SUCCESS) {
            ap_fgets(pid_str, sizeof(pid_str), pid_file);
            readpid = atol(pid_str);
            ap_close(pid_file);
        }
        if (!readpid)
        {
            ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                         "%s: could not retrieve pid from file %s",
		         display_name, pid_file);
            return;
        }
    }
    else
    {
        ap_log_error(APLOG_MARK, APLOG_STARTUP | APLOG_NOERRNO, 0, NULL, 
                     "%s: could not retrieve pid from file %s",
		     display_name, pid_file);
        return;
    }

    setup_signal_names(ap_psprintf(ptemp,"ap%d", (int) readpid));
    signal_parent(signal);
    if (signal)
        printf ("Signaled Service %s (pid %ld) to restart.", 
                display_name, readpid);
    else
        printf ("Signaled Service %s (pid %ld) to stop.", 
                display_name, readpid);
    return;
}
