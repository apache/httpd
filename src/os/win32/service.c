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
} globdat;

/* statics for atexit processing or shared between threads */
static BOOL  die_on_logoff = FALSE;
static DWORD monitor_thread_id = 0;
DWORD (WINAPI *RegisterServiceProcess)(DWORD, DWORD);
HINSTANCE    monitor_hkernel = NULL;


static void WINAPI service_main_fn(DWORD, LPTSTR *);
static void WINAPI service_ctrl(DWORD ctrlCode);
static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint);
static int ap_start_service(SC_HANDLE);
static int ap_stop_service(SC_HANDLE);

int service_main(int (*main_fn)(int, char **), int argc, char **argv )
{
    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "", service_main_fn },
        { NULL, NULL }
    };

    globdat.main_fn = main_fn;
    globdat.stop_event = create_event(0, 0, "apache-signal");
    globdat.connected = 1;

    if(!StartServiceCtrlDispatcher(dispatchTable))
    {
        /* This is a genuine failure of the SCM. */
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "Error starting service control dispatcher");
        return(globdat.exit_status);
    }
    else
    {
        return(globdat.exit_status);
    }
}

/* This is the WndProc procedure for our invisible window.
 * When the user shuts down the system, this window is sent
 * a signal WM_QUERYENDSESSION with lParam == 0 to indicate
 * a system shutdown. We clean up by shutting down Apache and
 * indicate to the system that the message was received and
 * understood (return TRUE).
 * If a user logs off, the window is sent WM_QUERYENDSESSION 
 * as well, but with lParam != 0. We ignore this case.
 */

int send_signal(pool *p, char *signal);

LRESULT CALLBACK Service9xWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (message == WM_QUERYENDSESSION)
    {
        /* Hmmm... not logging out, must be shutting down */
        if ((lParam == 0) || die_on_logoff)
        {
            /* Tell Apache to shut down gracefully */
            ap_start_shutdown();
	    if (wParam)
		Sleep(30000);
        }
        return TRUE;
    }
    return (DefWindowProc(hWnd, message, wParam, lParam));
}

DWORD WINAPI WatchWindow(void *service_name)
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
    wc.lpfnWndProc   = (WNDPROC) Service9xWndProc; 
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
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                     "Could not register window class for WatchWindow");
        return 0;
    }

    /* Create an invisible window */
    hwndMain = CreateWindow(wc.lpszClassName, 
			    service_name ? (char *) service_name : "Apache", 
                            WS_OVERLAPPEDWINDOW & ~WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 
                            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, NULL, NULL);

    if (!hwndMain)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
                     "Could not create WatchWindow");
        return 0;
    }
    
    while (GetMessage(&msg, NULL, 0, 0)) 
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

void stop_service_monitor(void)
{
    PostThreadMessage(monitor_thread_id, WM_QUIT, 0, 0);

    /* When the service quits, remove it from the 
       system service table */
    RegisterServiceProcess((DWORD)NULL, 0);

    /* Free the kernel library */
    FreeLibrary(monitor_hkernel);
}

int service95_main(int (*main_fn)(int, char **), int argc, char **argv, 
		   char *display_name)
{
    /* Windows 95/98 */
    char *service_name;
    HANDLE thread;
    
    /* Remove spaces from display name to create service name */
    service_name = strdup(display_name);
    ap_remove_spaces(service_name, display_name);

    /* Obtain a handle to the kernel library */
    monitor_hkernel = LoadLibrary("KERNEL32.DLL");
    if (!monitor_hkernel)
        return -1;
    
    /* Find the RegisterServiceProcess function */
    RegisterServiceProcess = (DWORD (WINAPI *)(DWORD, DWORD))
                   GetProcAddress(monitor_hkernel, "RegisterServiceProcess");
    if (RegisterServiceProcess == NULL)
        return -1;
	
    /* Register this process as a service */
    if (!RegisterServiceProcess((DWORD)NULL, 1))
        return -1;

    /* Hide the console */
    FreeConsole();

    thread = CreateThread(NULL, 0, WatchWindow, (LPVOID) service_name, 0, 
			  &monitor_thread_id);
    CloseHandle(thread);

    atexit(stop_service_monitor);

    /* Run the service */
    globdat.exit_status = main_fn(argc, argv);
}

void service_cd()
{
    /* change to the drive and directory with the executable */
    char buf[300], *p;
    GetModuleFileName(NULL, buf, 300);
    p = strrchr(buf, '\\');
    if (p != NULL)
        *p = 0;
    chdir(buf);
}

void __stdcall service_main_fn(DWORD argc, LPTSTR *argv)
{
    ap_server_argv0 = globdat.name = argv[0];

    if(!(globdat.hServiceStatus = RegisterServiceCtrlHandler( globdat.name, service_ctrl)))
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "Failure registering service handler");
        return;
    }

    ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000);                 // wait hint

    service_cd();
    if( service_init() ) 
        /* Arguments are ok except for \! */
        globdat.exit_status = (*globdat.main_fn)( argc, argv );
    
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

void InstallService(char *display_name, char *conf)
{
    TCHAR szPath[MAX_PATH];
    TCHAR szQuotedPath[512];
    char *service_name;

    printf("Installing the %s service to use %s\n", display_name, conf);

    if (GetModuleFileName( NULL, szPath, 512 ) == 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "GetModuleFileName failed");
        return;
    }

    /* Remove spaces from display name to create service name */
    service_name = strdup(display_name);
    ap_remove_spaces(service_name, display_name);

    if (isWindowsNT())
    {
        SC_HANDLE schService;
        SC_HANDLE schSCManager;

        ap_snprintf(szQuotedPath, sizeof(szQuotedPath), "\"%s\"", szPath);

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

        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL, 
		"CreateService failed");
        }

        CloseServiceHandle(schSCManager);
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

        /* Attempt to add a key for our service */
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
    }

    /* Both Platforms: Now store the server_root in the registry */
    if(!ap_registry_set_service_conf(conf, service_name))
        printf("The %s service has been installed successfully.\n", display_name);
}

void RemoveService(char *display_name)
{
    char *service_name;
    BOOL success = FALSE;

    printf("Removing the %s service\n", display_name);

    /* Remove spaces from display name to create service name */
    service_name = strdup(display_name);
    ap_remove_spaces(service_name, display_name);

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
        DWORD rv;

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
 *
 * TODO: be nice if we tested that it is an 'apache' service, no?
 */

BOOL isValidService(char *display_name) {
    char service_key[MAX_PATH];
    char *service_name;
    HKEY hkey;
    
    /* Remove spaces from display name to create service name */
    strcpy(service_key, "System\\CurrentControlSet\\Services\\");
    service_name = strchr(service_key, '\0');
    ap_remove_spaces(service_name, display_name);

    if (RegOpenKey(HKEY_LOCAL_MACHINE, service_key, &hkey) != ERROR_SUCCESS) {
        return FALSE;
    }
    RegCloseKey(hkey);
    return TRUE;
}

BOOL isWindowsNT(void)
{
    OSVERSIONINFO osver;
    osver.dwOSVersionInfoSize = sizeof(osver);

    if (GetVersionEx(&osver))
        if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
            return TRUE;

    return FALSE;
}

int send_signal_to_service(char *display_name, char *sig) {
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

    /* Remove spaces from display name to create service name */
    service_name = strdup(display_name);
    ap_remove_spaces(service_name, display_name);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if (!schSCManager) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "OpenSCManager failed");
    }
    else {
        schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL) {
            /* Could not open the service */
           ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
            "OpenService failed");
        }
        else {
            if (!QueryServiceStatus(schService, &globdat.ssStatus))
                ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
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

/* Control handler for processing Ctrl-C/Ctrl-Break and
 * on Windows NT also user logoff and system shutdown
 */

static BOOL CALLBACK ap_control_handler(DWORD ctrl_type)
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
            ap_start_shutdown();
            return TRUE;

        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            /* for Terminate signals, shut down the server.
             * Wait for Apache to terminate, but respond
             * after a reasonable time to tell the system
             * that we have already tried to shut down.
             */
            fprintf(stderr, "Apache server shutdown initiated...\n");
            ap_start_shutdown();
            Sleep(30000);
            return TRUE;
    }
 
    /* We should never get here, but this is (mostly) harmless */
    return FALSE;
}

void stop_console_monitor(void)
{
    if (!isWindowsNT() && monitor_thread_id)
	PostThreadMessage(monitor_thread_id, WM_QUIT, 0, 0);

    /* Remove the control handler at the end of the day. */
    SetConsoleCtrlHandler(ap_control_handler, FALSE);
}

void ap_start_console_monitor(void)
{
    /* Under 95/98 create a monitor window to watch for session end,
     * pass NULL to WatchWindow so we do not appear to run as a service.
     */
    SetConsoleCtrlHandler(ap_control_handler, TRUE);
    
    if (!isWindowsNT()) {
        HANDLE thread;
        thread = CreateThread(NULL, 0, WatchWindow, NULL, 0, 
                              &monitor_thread_id);
        CloseHandle(thread);
    }

    atexit(stop_console_monitor);
}
#endif /* WIN32 */

