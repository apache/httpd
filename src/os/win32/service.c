
#ifdef WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <direct.h>

#include "../multithread.h"
#include "service.h"


static struct
{
    int (*main_fn)(int, char **);
    event *stop_event;
    int *stop_flag;
    int *pause_flag;
    int connected;
    SERVICE_STATUS_HANDLE hServiceStatus;
    char *name;
    int exit_status;
    SERVICE_STATUS ssStatus;
    FILE *logFile;
} globdat;

static void WINAPI service_main_fn(DWORD, char **);
static void WINAPI service_ctrl(DWORD ctrlCode);
static int ReportStatusToSCMgr(int currentState, int exitCode, int waitHint);
static void InstallService();
static void RemoveService();


int service_main(int (*main_fn)(int, char **), int argc, char **argv,
                  int *pause, int *stop, char *service_name,
                  int install_flag, int run_as_service)
{
    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { service_name, service_main_fn },
        { NULL, NULL }
    };

    globdat.name = service_name;

    if(install_flag > 0)
    {
        InstallService();
        return(0);
    }
    else if(install_flag < 0)
    {
        RemoveService();
        return(0);
    }
    else
    {
        globdat.main_fn = main_fn;
        globdat.stop_event = create_event(0, 0, NULL);
        globdat.stop_flag = stop;
        globdat.pause_flag = pause;
     
        if(run_as_service)
        {
            globdat.connected = 1;
            if(!StartServiceCtrlDispatcher(dispatchTable))
            {
                return((*main_fn)(argc, argv));
            }
            else
            {
                return(globdat.exit_status);
            }
        }
        else
        {
            globdat.connected = 0;
            return((*main_fn)(argc, argv));
        }
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

void __stdcall service_main_fn(DWORD argc, char **argv)
{


    if(!(globdat.hServiceStatus = RegisterServiceCtrlHandler( globdat.name, service_ctrl)))
    {
        globdat.exit_status = -1;
        return;
    }


    ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000);                 // wait hint

    globdat.exit_status = (*globdat.main_fn)( argc, argv );


    ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);

    return;
}

void
service_set_status(int status)
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
            *(globdat.stop_flag) = 1;
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


void InstallService()
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    TCHAR szPath[512];

    if ( GetModuleFileName( NULL, szPath, 512 ) == 0 )
    {
        exit(1);
        return;
    }

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if ( schSCManager )
    {
        schService = CreateService(
            schSCManager,               // SCManager database
            globdat.name,        // name of service
            globdat.name, // name to display
            SERVICE_ALL_ACCESS,         // desired access
            SERVICE_WIN32_OWN_PROCESS,  // service type
            SERVICE_AUTO_START,       // start type
            SERVICE_ERROR_NORMAL,       // error control type
            szPath,                     // service's binary
            NULL,                       // no load ordering group
            NULL,                       // no tag identifier
            NULL,       // dependencies
            NULL,                       // LocalSystem account
            NULL);                      // no password

        if ( schService )
        {
            CloseServiceHandle(schService);
        }
        else
        {
        }

        CloseServiceHandle(schSCManager);
    }

}




void RemoveService()
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if ( schSCManager )
    {
        schService = OpenService(schSCManager, globdat.name, SERVICE_ALL_ACCESS);

        /* try to stop the service */
        if(ControlService(schService, SERVICE_CONTROL_STOP, &globdat.ssStatus))
        {
            Sleep(1000);
            while(QueryServiceStatus(schService, &globdat.ssStatus))
            {
                if(globdat.ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
                    Sleep(1000);
                else
                    break;
            }
        }

        if (schService)
        {
            // now remove the service
            DeleteService(schService);
            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

}

#endif /* WIN32 */


