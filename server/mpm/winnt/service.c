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

void service_cd()
{
    /* change to the drive with the executable */
    char buf[300];
    GetModuleFileName(NULL, buf, 300);
    buf[2] = 0;
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

void InstallService(char *service_name, char *conf)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    TCHAR szPath[512];
    TCHAR szQuotedPath[512];

    printf("Installing the %s service to use %s\n", service_name, conf);

    if (GetModuleFileName( NULL, szPath, 512 ) == 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "GetModuleFileName failed");
        return;
    }

    ap_snprintf(szQuotedPath, 512, "\"%s\"", szPath);

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
        schService = CreateService(
            schSCManager,               // SCManager database
            service_name,               // name of service
            service_name,               // name to display
            SERVICE_ALL_ACCESS,         // desired access
            SERVICE_WIN32_OWN_PROCESS,  // service type
            SERVICE_AUTO_START,       // start type
            SERVICE_ERROR_NORMAL,       // error control type
            szQuotedPath,               // service's binary
            NULL,                       // no load ordering group
            NULL,                       // no tag identifier
            NULL,       // dependencies
            NULL,                       // LocalSystem account
            NULL);                      // no password

        if (schService) {
            CloseServiceHandle(schService);

            /* Now store the server_root in the registry */
            if(!ap_registry_set_service_conf(conf, service_name))
                printf("The %s service has been installed successfully.\n", service_name );
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL, 
		"CreateService failed");
        }

        CloseServiceHandle(schSCManager);
    }
}


void RemoveService(char *service_name)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    printf("Removing the %s service\n", service_name);

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
            /* try to stop the service */
            ap_stop_service(schService);

            // now remove the service
            if (DeleteService(schService) == 0)
		ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
		    "DeleteService failed");
            else
                printf("The %s service has been removed successfully.\n", service_name );
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
 */

BOOL isValidService(char *service_name) {
    SC_HANDLE schSCM, schSVC;
    int Err;

    if (!(schSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS))) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
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
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_WIN32ERROR, NULL,
        "OpenService failed");

    return FALSE;
}

int send_signal_to_service(char *service_name, char *sig) {
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;
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
                    printf("The %s service is not started.\n", service_name);
                else if (globdat.ssStatus.dwCurrentState == SERVICE_RUNNING && action == start)
                    printf("The %s service has already been started.\n", service_name);
                else {
                    printf("The %s service is %s.\n", service_name, participle[action]);

                    if (action == stop || action == restart)
                        success = ap_stop_service(schService);
                    if (action == start || action == restart)
                        success = ap_start_service(schService);
                
                    if( success )
                        printf("The %s service has %s.\n", service_name, past[action]);
                    else
                        printf("Failed to %s the %s service.\n", sig, service_name );
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

