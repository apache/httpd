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

#ifdef WIN32

#define  CORE_PRIVATE 

#include "main_win32.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_conf_globals.h"
#include "http_log.h"
#include "service.h"
#include "registry.h"
#include "ap_mpm.h"
#include "..\..\modules\mpm\winnt\winnt.h"

typedef void (CALLBACK *ap_completion_t)();
API_EXPORT_VAR ap_completion_t ap_mpm_init_complete;
API_EXPORT_VAR char *ap_server_argv0;

static struct
{
    int (*main_fn)(int, char **);
    event *stop_event;
    int connected;
    SERVICE_STATUS_HANDLE hServiceStatus;
    char *name;
    int exit_status;
    SERVICE_STATUS ssStatus;
    FILE *logFile;
    char *service_dir;
    HANDLE threadService;
    HANDLE threadMonitor;
} globdat;

static void WINAPI service_main_fn(DWORD, LPTSTR *);
static void WINAPI service_ctrl(DWORD ctrlCode);
static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint);
static int ap_start_service(SC_HANDLE);
static int ap_stop_service(SC_HANDLE);

static LRESULT CALLBACK MonitorWin9xWndProc(HWND hWnd, UINT msg, 
                                            WPARAM wParam, LPARAM lParam)
{
/* This is the WndProc procedure for our invisible window.
 * When the user shuts down the system, this window is sent
 * a signal WM_ENDSESSION. We clean up by signaling Apache
 * to shut down, and idle until Apache's primary thread quits.
 */
    if ((msg == WM_ENDSESSION) && (lParam != ENDSESSION_LOGOFF))
    {
        ap_start_shutdown();
	if (wParam)
	    WaitForSingleObject(globdat.threadService, 30000);
        return 0;
    }
    return (DefWindowProc(hWnd, msg, wParam, lParam));
}

static DWORD WINAPI MonitorWin9xEvents(LPVOID initEvent)
{
/* When running on Windows 9x, the ConsoleCtrlHandler is _NOT_ 
 * called when the system is shutdown.  So create an invisible 
 * window to watch for the WM_ENDSESSION message, and watch for
 * the WM_CLOSE message to shut the window down.
 */
    WNDCLASS wc;
    HWND hwndMain;

    wc.style         = CS_GLOBALCLASS;
    wc.lpfnWndProc   = MonitorWin9xWndProc; 
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 0; 
    wc.hInstance     = NULL;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = "ApacheWin9xService";
 
    if (RegisterClass(&wc)) 
    {
        /* Create an invisible window */
        hwndMain = CreateWindow("ApacheWin9xService", "Apache", 
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
            globdat.threadMonitor = 0;
            return(0);
        }
    }
    /* We failed or are soon to die... 
     * we won't need this much longer 
     */
    SetEvent((HANDLE) initEvent);
    globdat.threadMonitor = 0;
    return(0);
}

static void CALLBACK report_service9x_running()
{
}

int service9x_main(int (*main_fn)(int, char **), int argc, char **argv )
{
    DWORD (WINAPI *RegisterServiceProcess)(DWORD, DWORD);
    HINSTANCE hkernel;
    DWORD threadId;
    
    globdat.threadService = GetCurrentThread();
    
    /* Obtain a handle to the kernel library */
    hkernel = LoadLibrary("KERNEL32.DLL");
    if (hkernel) {
        /* Find the RegisterServiceProcess function */
        RegisterServiceProcess = (DWORD (WINAPI *)(DWORD, DWORD))
                                 GetProcAddress(hkernel, "RegisterServiceProcess");
        if (RegisterServiceProcess) {
            if (RegisterServiceProcess((DWORD)NULL, 1)) {
                HANDLE installed = CreateEvent(NULL, FALSE, FALSE, NULL);
                globdat.threadMonitor = CreateThread(NULL, 0,
                                                     MonitorWin9xEvents, 
                                                     (LPVOID) installed,
                                                     0, &threadId);
                WaitForSingleObject(installed, 30000);
                CloseHandle(installed);
            }
        }
    }

    /* Run the service */
    globdat.exit_status = main_fn(argc, argv);

    /* Still have a thread & window to clean up, so signal now */
    if (globdat.threadMonitor)
    {
	PostThreadMessage(threadId, WM_CLOSE, 0, 0);
        WaitForSingleObject(globdat.threadMonitor, 30000);
    }

    /* When the service quits, remove it from the 
       system service table */
    if (RegisterServiceProcess)
	RegisterServiceProcess((DWORD)NULL, 0);

    /* Free the kernel library */
    if (hkernel)
        FreeLibrary(hkernel);

    return (globdat.exit_status);
}

int servicent_main(int (*main_fn)(int, char **), int argc, char **argv )
{
    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "", service_main_fn },
        { NULL, NULL }
    };

    globdat.main_fn = main_fn;
    globdat.stop_event = CreateEvent(NULL, 0, 0, "apache-signal");
    globdat.connected = 1;
    globdat.service_dir = argv[0];

    if(!StartServiceCtrlDispatcher(dispatchTable))
    {
        /* This is a genuine failure of the SCM. */
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                     "Error starting service control dispatcher");
        return(globdat.exit_status);
    }
    else
    {
        return(globdat.exit_status);
    }
}

static void CALLBACK report_servicent_started()
{
    ReportStatusToSCMgr(
        SERVICE_RUNNING,    // service state
        NO_ERROR,           // exit code
        0);                 // wait hint
}

void __stdcall service_main_fn(DWORD argc, LPTSTR *argv)
{
    int i, new_argc;
    char **new, *server_root, *tmp;
    char *server_confname = SERVER_CONFIG_FILE;
    ap_array_header_t *cmdtbl;
    ap_pool_t *pwincmd;

    ap_create_pool(&pwincmd, NULL);
    if (pwincmd == NULL) {
        exit(0);
    }

    ap_server_argv0 = globdat.name = argv[0];
    cmdtbl = ap_make_array(pwincmd, 1, sizeof(char *));

    server_root = ap_pstrdup(pwincmd, globdat.service_dir); 
    tmp = strrchr(server_root, '\\');
    *tmp = '\0';

    if(!(globdat.hServiceStatus = RegisterServiceCtrlHandler( globdat.name, service_ctrl)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
        "Failure registering service handler");
        return;
    }

    ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000);                 // wait hint

    ap_mpm_init_complete = report_servicent_started;

    /* Fetch server_conf from the registry 
     *  Rebuild argv and argc adding the -d server_root and -f server_conf then 
     *  call apache_main
     */
    ap_registry_get_service_conf(pwincmd, &server_confname, argv[0]);
    for (i = 0; i < argc ; i++) {
        new = (char **) ap_push_array(cmdtbl);
        *new = argv[i];
    }
    /* Add server_confname to the argument list */
    new = (char **) ap_push_array(cmdtbl);
    *new = "-f";
    new = (char **) ap_push_array(cmdtbl);
    *new = server_confname;
    new = (char **) ap_push_array(cmdtbl);
    *new = "-d";
    new = (char **) ap_push_array(cmdtbl);
    *new = server_root;
    new_argc = argc + 4;

    globdat.exit_status = (*globdat.main_fn)( new_argc, (char**) cmdtbl->elts );
    
    ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);

    return;
}

void service_set_status(int status)
{
    ReportStatusToSCMgr(status, NO_ERROR, 3000);
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
//  COMMENTS:
//
VOID WINAPI service_ctrl(DWORD dwCtrlCode)
{
    int state;

    state = globdat.ssStatus.dwCurrentState;
    switch(dwCtrlCode)
    {
        // Stop the service.
        //
        case SERVICE_CONTROL_STOP:
            state = SERVICE_STOP_PENDING;
	    ap_start_shutdown();
            break;

        // Update the service status.
        //
        case SERVICE_CONTROL_INTERROGATE:
            break;

        // invalid control code
        //
        default:
            break;

    }

    ReportStatusToSCMgr(state, NO_ERROR, 0);
}


int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint)
{
    static int firstTime = 1;
    static int checkPoint = 1;
    int rv;
    
    if(firstTime)
    {
        firstTime = 0;
        globdat.ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        globdat.ssStatus.dwServiceSpecificExitCode = 0;
        globdat.ssStatus.dwCheckPoint = 1;
    }

    if(globdat.connected)
    {
        if (currentState == SERVICE_START_PENDING)
            globdat.ssStatus.dwControlsAccepted = 0;
        else
            globdat.ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

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
    return(1);
}

void InstallServiceNT(char *display_name, char *conf)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    TCHAR szPath[512];
    TCHAR szQuotedPath[512];
    char service_name[256];

    printf("Installing the %s service to use %s\n", display_name, conf);

    if (GetModuleFileName( NULL, szPath, 512 ) == 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
        "GetModuleFileName failed");
        return;
    }

    /* Remove spaces from display name to create service name */
    ap_collapse_spaces(service_name, display_name);

    ap_snprintf(szQuotedPath, 512, "\"%s\"", szPath);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
   if (!schSCManager) {
       ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                    "OpenSCManager failed");
    }
    else {
    /* Added dependencies for the following: TCPIP, AFD
     * AFD is the winsock handler, TCPIP is self evident
     *
     * RPCSS is the Remote Procedure Call (RPC) Locator
     * required for DCOM communication.  I am far from
     * convinced we should toggle this, but be warned that
     * future apache modules or ISAPI dll's may depend on it.
     */
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
            "Tcpip\0Afd\0",             // dependencies
            NULL,                       // LocalSystem account
            NULL);                      // no password

        if (schService) {
            CloseServiceHandle(schService);

            /* Now store the server_root in the registry */
            if(!ap_registry_set_service_conf(conf, service_name))
                printf("The %s service has been installed successfully.\n", display_name);
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL, 
                         "CreateService failed");
        }

        CloseServiceHandle(schSCManager);
    }
}


void RemoveServiceNT(char *display_name)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;
    char service_name[256];

    printf("Removing the %s service\n", display_name);

    /* Remove spaces from display name to create service name */
    ap_collapse_spaces(service_name, display_name);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if (!schSCManager) {
       ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                    "OpenSCManager failed");
    }
    else {
        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
           ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
			"OpenService failed");
        }
        else {
            /* try to stop the service */
            ap_stop_service(schService);

            // now remove the service
            if (DeleteService(schService) == 0)
		ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                             "DeleteService failed");
            else
                printf("The %s service has been removed successfully.\n", display_name);
            CloseServiceHandle(schService);
        }
        /* SCM removes registry parameters  */
        CloseServiceHandle(schSCManager);
    }

}

/* A hack to determine if we're running as a service without waiting for
 * the SCM to fail; if AllocConsole succeeds, we're a service.
 */

BOOL isProcessService() {
    if( !AllocConsole() ) 
        return FALSE;
    FreeConsole();
    return TRUE;
}

/* Determine is service_name is a valid service
 * Simplify by testing the registry rather than the SCM
 * as this will work on both WinNT and Win9x.
 */

BOOL isValidService(ap_pool_t *p, char *display_name) {
    char service_name[256];
    char *service_conf;

    /* Remove spaces from display name to create service name */
    ap_collapse_spaces(service_name, display_name);

    if(ap_registry_get_service_conf(p, &service_conf, service_name)) {
        return TRUE;
    }
    
    return FALSE;

#if 0
    SC_HANDLE schSCM, schSVC;
    int Err;

    if (!(schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS))) {
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                     "OpenSCManager failed");
       return FALSE;
    }

    if ((schSVC = OpenService(schSCM, service_name, SERVICE_ALL_ACCESS))) {
        CloseServiceHandle(schSVC);
        CloseServiceHandle(schSCM);
        return TRUE;
    }

    Err = GetLastError();
    if (Err != ERROR_SERVICE_DOES_NOT_EXIST && Err != ERROR_INVALID_NAME)
        ap_log_error(APLOG_MARK, APLOG_ERR, Err, NULL,
                     "OpenService failed");

    return FALSE;
#endif
}

/* Although the Win9x service enhancement added -k startservice,
 * it is never processed here, so we still ignore that param.
 */
int send_signal_to_service(char *display_name, char *sig) {
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;
    char service_name[256];
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

    /* Remove spaces from display name to create service name */
    ap_collapse_spaces(service_name, display_name);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if (!schSCManager) {
        ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                     "OpenSCManager failed");
    }
    else {
        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
           ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                        "OpenService failed");
        }
        else {
            if (!QueryServiceStatus(schService, &globdat.ssStatus))
                ap_log_error(APLOG_MARK, APLOG_ERR, GetLastError(), NULL,
                             "QueryService failed");
            else {
                if (globdat.ssStatus.dwCurrentState == SERVICE_STOPPED && action == stop)
                    printf("The %s service is not started.\n", display_name);
                else if (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING && action == start)
                    printf("The %s service has already been started.\n", display_name);
                else {
                    printf("The %s service is %s.\n", display_name, participle[action]);

                    if (action == stop || action == restart)
                        success = ap_stop_service(schService);
                    if (action == start || action == restart)
                        success = ap_start_service(schService);
                
                    if( success )
                        printf("The %s service has %s.\n", display_name, past[action]);
                    else
                        printf("Failed to %s the %s service.\n", sig, display_name);
                }

                CloseServiceHandle(schService);
            }
        }
        /* SCM removes registry parameters */
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

int ap_start_service(SC_HANDLE schService) {
    if (StartService(schService, 0, NULL)) {
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

#endif /* WIN32 */

