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

/* ====================================================================
 * ApacheMonitor.c Simple program to manage and monitor Apache services.
 *
 * Contributed by Mladen Turk <mturk@mappingsoft.com>
 *
 * 05 Aug 2001
 * ==================================================================== 
 */

#define _WIN32_WINNT 0x0400
#ifndef STRICT
#define STRICT
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <stdlib.h>
#include <stdio.h>
#include "ApacheMonitor.h"


#define OS_VERSION_WINNT    1
#define OS_VERSION_WIN9X    2
#define OS_VERSION_WIN2K    3
/* Should be enough */
#define MAX_APACHE_SERVICES 128

#define WM_TRAYMESSAGE         (WM_APP+1)
#define WM_UPDATEMESSAGE       (WM_USER+1)
#define WM_TIMER_REFRESH       10
#define WM_TIMER_RESCAN        11
#define SERVICE_APACHE_RESTART 128
#define XBITMAP                16
#define YBITMAP                16 
#define MAX_LOADSTRING         100
#define REFRESH_TIME           1000           /* service refresh time (ms) */
#define RESCAN_TIME            10000          /* registry rescan time (ms) */

typedef struct _st_APACHE_SERVICE
{
    LPSTR    szServiceName;
    LPSTR    szDisplayName;
    LPSTR    szDescription;
    LPSTR    szImagePath;
    DWORD    dwPid;
} ST_APACHE_SERVICE;

/* Global variables */
HINSTANCE         ap_hInstance = NULL;
HWND              ap_hwndAboutDlg = NULL;
TCHAR             szTitle[MAX_LOADSTRING];          /* The title bar text */
TCHAR             szWindowClass[MAX_LOADSTRING];    /* Window Class Name  */
HICON             ap_icoStop;
HICON             ap_icoRun;
UINT              ap_uiTaskbarCreated;
DWORD             ap_OSVersion;
BOOL              dlgAboutOn = FALSE;
BOOL              dlgServiceOn = FALSE;
BOOL              ap_consoleRun = FALSE;
ST_APACHE_SERVICE ap_stServices[MAX_APACHE_SERVICES];

HBITMAP           hbmpStart, hbmpStop; 
HBITMAP           hbmpPicture, hbmpOld; 
BOOL              ap_rescanServices;
HWND              ap_hServiceDlg;
HWND              ap_hMainWnd;
HWND              ap_hStdoutWnd;
HCURSOR           ap_cHourglass;
HCURSOR           ap_cArrow;

HANDLE            h_stdOutR;
HANDLE            h_stdOutW;
HANDLE            h_stdInR;
HANDLE            h_stdInW;
HANDLE            h_stdErr;
PROCESS_INFORMATION ap_redirectedPI;

void ap_ClearServicesSt()
{
    int i;
    for (i = 0; i < MAX_APACHE_SERVICES; i++)
    {
        if (ap_stServices[i].szServiceName)
            free(ap_stServices[i].szServiceName);
        if (ap_stServices[i].szDisplayName)
            free(ap_stServices[i].szDisplayName);
        if (ap_stServices[i].szDescription)
            free(ap_stServices[i].szDescription);
        if (ap_stServices[i].szImagePath)
            free(ap_stServices[i].szImagePath);

    }
    ZeroMemory(ap_stServices, sizeof(ST_APACHE_SERVICE) * MAX_APACHE_SERVICES);

}

void ErrorMessage(DWORD dwError)
{
    LPVOID lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  dwError == ERROR_SUCCESS ? GetLastError() : dwError,
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                  (LPTSTR) &lpMsgBuf, 0, NULL);
    MessageBox(NULL, (LPCTSTR)lpMsgBuf, "Error", MB_OK | MB_ICONERROR);
    LocalFree(lpMsgBuf);

}

LPTSTR GetStringRes(int id)
{
  static TCHAR buffer[MAX_PATH];

  buffer[0] = 0;
  LoadString(GetModuleHandle (NULL), id, buffer, MAX_PATH);
  return buffer;
}

BOOL GetSystemOSVersion(LPSTR szVersion, LPDWORD dwVersion)
{
    OSVERSIONINFOEX osvi;
    BOOL    bOsVersionInfoEx;
    char    szBuff[256];
    HKEY    hKey;
    char    szProductType[80];
    DWORD   dwBufLen;
    
    /* 
    Try calling GetVersionEx using the OSVERSIONINFOEX structure.
    If that fails, try using the OSVERSIONINFO structure.
    */
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    
    if (!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *) &osvi)))
    {
        /* If OSVERSIONINFOEX doesn't work, try OSVERSIONINFO. */        
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *) &osvi)) 
            return FALSE;
    }
    
    switch (osvi.dwPlatformId)
    {
    case VER_PLATFORM_WIN32_NT:        
        /* Test for the product. */        
        if (szVersion!= NULL)
        {
            if (osvi.dwMajorVersion <= 4)
                strcpy(szVersion, "MS Windows NT ");
            else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
                strcpy(szVersion, "MS Windows 2000 ");
            else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
                strcpy(szVersion, "Whistler ");
            /* Test for product type.*/            
#ifdef VER_VORKSTATION_NT
            if (bOsVersionInfoEx)
            {
                if (osvi.wProductType == VER_NT_WORKSTATION)
                {
#ifdef VER_SUITE_PERSONAL
                    if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
                        strcat(szVersion, "Personal ");
                    else
#endif
                    strcat(szVersion, "Professional ");
                }                
                else if (osvi.wProductType == VER_NT_SERVER)
                {
                    if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
                        strcat(szVersion, "DataCenter Server ");
                    else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
                        strcat(szVersion, "Advanced Server ");
                    else
                        strcat(szVersion, "Server ");
                }
            }
            else
            {
#endif                
                RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
                    0, KEY_QUERY_VALUE, &hKey);
                RegQueryValueEx(hKey, "ProductType", NULL, NULL,
                    (LPBYTE) szProductType, &dwBufLen);
                RegCloseKey(hKey);
                if (lstrcmpi("WINNT", szProductType) == 0)
                    strcat(szVersion, "Workstation ");
                if (lstrcmpi("SERVERNT", szProductType) == 0)
                    strcat(szVersion, "Server ");
#ifdef VER_VORKSTATION_NT
            }            
#endif
            /* Get version, service pack (if any), and build number. */
            if (osvi.dwMajorVersion <= 4)
            {
                sprintf(szBuff, "version %d.%d %s (Build-%d)\n",
                        osvi.dwMajorVersion,
                        osvi.dwMinorVersion,
                        osvi.szCSDVersion,
                        osvi.dwBuildNumber & 0xFFFF);
            }
            else
            { 
                sprintf(szBuff, "%s (Build-%d)\n",
                    osvi.szCSDVersion,
                    osvi.dwBuildNumber & 0xFFFF);
            }
            strcat(szVersion, szBuff);
        }
        else if (dwVersion != NULL)
        {
            if (osvi.dwMajorVersion <= 4)
                *dwVersion = OS_VERSION_WINNT;
            else if (osvi.dwMajorVersion == 5)
                *dwVersion = OS_VERSION_WIN2K;
            else
                return FALSE;
            
        }
        break;
        
    case VER_PLATFORM_WIN32_WINDOWS:
        if (szVersion != NULL)
        {
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0)
            {
                strcpy(szVersion, "MS Windows 95 ");
                if (osvi.szCSDVersion[1] == 'C')
                    strcat(szVersion, "OSR2 ");
            } 
            
            if(osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10)
            {
                strcpy(szVersion, "MS Windows 98 ");
                if (osvi.szCSDVersion[1] == 'A')
                    strcat(szVersion, "SE ");
            } 
            
            if(osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90)
            {
                strcpy(szVersion, "MS Windows Me ");
            }
        }
        if (dwVersion != NULL)
            *dwVersion = OS_VERSION_WIN9X;
        
        break;
        
    case VER_PLATFORM_WIN32s:
        if (szVersion != NULL)
            strcpy(szVersion, "Microsoft Win32s ");
        if (dwVersion != NULL)
            *dwVersion = OS_VERSION_WIN9X;
        break;
    default:
        return FALSE;
        break;
   }
   return TRUE; 
}

static VOID ShowNotifyIcon(HWND hWnd, DWORD dwMessage)
{
    
    NOTIFYICONDATA nid;
    int  i = 0, n = 0;

    ZeroMemory(&nid,sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWnd;
    nid.uID = 0xFF;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYMESSAGE;
    
    while (ap_stServices[i].szServiceName != NULL)
    {    
        if (ap_stServices[i].dwPid != 0)
            ++n;
        ++i;
    }
    if (dwMessage != NIM_DELETE)
    {
        if (n)
            nid.hIcon = ap_icoRun;
        else
            nid.hIcon = ap_icoStop;
    }
    else
        nid.hIcon = NULL;
    if (n == i)
        lstrcpy(nid.szTip, "Running all Apache services");
    else if (n)
        sprintf(nid.szTip, "Running %d from %d Apache services", n, i);
    else
        sprintf(nid.szTip, "Running none from %d Apache services", n, i);

    Shell_NotifyIcon(dwMessage, &nid);
    
}

void appendMenuItem(HMENU hMenu, UINT uMenuId, LPSTR szName, BOOL fDefault)
{
    MENUITEMINFO mii;
    
    ZeroMemory(&mii, sizeof(MENUITEMINFO));
    mii.cbSize = sizeof(MENUITEMINFO);
    mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE;
    if (lstrlen(szName))
    {
        mii.fType = MFT_STRING;
        mii.wID = uMenuId;
        if (fDefault)
            mii.fState = MFS_DEFAULT;
        mii.dwTypeData = szName;
    }
    else
        mii.fType = MFT_SEPARATOR;
    InsertMenuItem(hMenu, uMenuId, FALSE, &mii);
}

void ShowTryPopupMenu(HWND hWnd)
{
    /* create popup menu */
    HMENU hMenu = CreatePopupMenu();
    POINT pt;

    if (hMenu)
    {
        appendMenuItem(hMenu,  IDM_ABOUT, "&About...", FALSE);
        appendMenuItem(hMenu,  IDM_RESTORE, "&Show Services...", TRUE);
        appendMenuItem(hMenu,  0, "", FALSE);
        appendMenuItem(hMenu,  IDM_EXIT,  "&Exit...", FALSE);

        GetCursorPos(&pt);
        SetForegroundWindow(NULL);
        TrackPopupMenu(hMenu, TPM_LEFTALIGN|TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, NULL);
    }
}

BOOL CenterWindow(HWND hwndChild)
{
   RECT    rChild, rWorkArea;
   int     wChild, hChild;
   int     xNew, yNew;
   BOOL    bResult;

   /* Get the Height and Width of the child window */
   GetWindowRect(hwndChild, &rChild);
   wChild = rChild.right - rChild.left;
   hChild = rChild.bottom - rChild.top;

   /* Get the limits of the 'workarea' */
   bResult = SystemParametersInfo(
      SPI_GETWORKAREA,
      sizeof(RECT),
      &rWorkArea,
      0);
   if (!bResult) {
      rWorkArea.left = rWorkArea.top = 0;
      rWorkArea.right = GetSystemMetrics(SM_CXSCREEN);
      rWorkArea.bottom = GetSystemMetrics(SM_CYSCREEN);
   }

   /* Calculate new X and Y position*/
   xNew = (rWorkArea.right - wChild)/2;
   yNew = (rWorkArea.bottom - hChild)/2;
   return SetWindowPos (hwndChild, HWND_TOP, xNew, yNew, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
}

static void addItem(HWND hDlg, LPSTR lpStr, HBITMAP hBmp) 
{ 
    int nItem; 
 
    nItem = SendMessage(hDlg, LB_ADDSTRING, 0, (LPARAM)lpStr); 
    SendMessage(hDlg, LB_SETITEMDATA, nItem, (LPARAM)hBmp); 
} 

static DWORD WINAPI ConsoleOutputThread(LPVOID lpThreadParameter)
{
    static BYTE lpBuffer[513];
    LPSTR lpBuf = lpBuffer;
    BYTE  ch;
    DWORD dwReaded;

    while (ReadFile(h_stdOutR, &ch, 1, &dwReaded, NULL) == TRUE) 
    {
        if (dwReaded > 0) 
        {
            if (ch == '\n') 
            {
                *lpBuf = '\0';
                ListBox_SetCurSel(ap_hStdoutWnd,
                                  ListBox_AddString(ap_hStdoutWnd, lpBuffer));
                lpBuf = lpBuffer;
            } 
            else if (ch == '\t') 
            {
                int i, t;
                t = ((int)lpBuf - (int)lpBuffer) % 8;
                for (i = 0; i < 8 - t; ++i)
                    *lpBuf++ = ' ';
            }
            else if (ch != '\r')
                *lpBuf++ = ch;
        }
    }
    CloseHandle(h_stdInW);
    CloseHandle(h_stdOutR);
    CloseHandle(h_stdErr);
    return 0;
}


DWORD WINAPI ConsoleWaitingThread(LPVOID lpThreadParameter)
{
    WaitForSingleObject(ap_redirectedPI.hThread, INFINITE);
    CloseHandle(ap_redirectedPI.hThread);
    MessageBeep(100);
    ap_consoleRun = FALSE;
    SetCursor(ap_cArrow);
    return 0;
}


BOOL RunRedirectedConsole(LPTSTR szCmdLine, LPDWORD nRetValue)
{
    
    DWORD  dwThreadId;
    HANDLE hProc;
    STARTUPINFO stInfo;
    BOOL bResult;
    ZeroMemory(&stInfo, sizeof(stInfo));
    stInfo.cb = sizeof(stInfo);
    stInfo.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    stInfo.wShowWindow = SW_HIDE;
    
    hProc = GetCurrentProcess();

    if (!CreatePipe(&h_stdInR, &h_stdInW, NULL, MAX_PATH))
        ErrorMessage(ERROR_SUCCESS);
    if (!CreatePipe(&h_stdOutR, &h_stdOutW, NULL, MAX_PATH*8))
        ErrorMessage(ERROR_SUCCESS);
        
    DuplicateHandle(hProc, h_stdInR, hProc, &h_stdInR, 0, TRUE, 
                    DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS);
    DuplicateHandle(hProc, h_stdOutW, hProc, &h_stdOutW, 0, TRUE, 
                    DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS);
    DuplicateHandle(hProc, h_stdOutW, hProc, &h_stdErr, 0, TRUE, 
                    DUPLICATE_SAME_ACCESS);
    
    stInfo.hStdInput  = h_stdInR;
    stInfo.hStdOutput = h_stdOutW;
    stInfo.hStdError  = h_stdErr;

    bResult = CreateProcess(NULL,
        szCmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL ,
        &stInfo,
        &ap_redirectedPI);


    CloseHandle(h_stdInR);
    CloseHandle(h_stdOutW);
    CloseHandle(h_stdErr);

    if (!bResult)
    {     
        if (nRetValue)
            *nRetValue = GetLastError();
        CloseHandle(h_stdInW);
        CloseHandle(h_stdOutR);
        CloseHandle(h_stdErr);
        return FALSE;
    }

    CloseHandle(CreateThread(NULL, 0, ConsoleOutputThread, 0, 0, &dwThreadId));
    ResumeThread(ap_redirectedPI.hThread);
    CloseHandle(CreateThread(NULL, 0, ConsoleWaitingThread, 0, 0, &dwThreadId));

    return TRUE;
}

BOOL RunAndForgetConsole(LPTSTR szCmdLine,
                         LPDWORD nRetValue,
                         BOOL  bRedirectConsole)
{
        
    STARTUPINFO stInfo;
    PROCESS_INFORMATION prInfo;
    BOOL bResult;
    
    if (bRedirectConsole)
        return RunRedirectedConsole(szCmdLine, nRetValue);

    
    ZeroMemory(&stInfo, sizeof(stInfo));
    stInfo.cb = sizeof(stInfo);
    stInfo.dwFlags = STARTF_USESHOWWINDOW;
    stInfo.wShowWindow = SW_HIDE;

    bResult = CreateProcess(NULL,
        szCmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL ,
        &stInfo,
        &prInfo);

    if (!bResult)
    {     
        if (nRetValue)
            *nRetValue = GetLastError();
        return FALSE;
    }
    if (ap_OSVersion == OS_VERSION_WIN9X) /* give some time to rescan the status */
        Sleep(2000);
    CloseHandle(prInfo.hThread);
    CloseHandle(prInfo.hProcess);
    return TRUE;
}

BOOL ApacheManageService(LPCSTR szServiceName, LPCSTR szImagePath, DWORD dwCommand)
{
    
    CHAR      szBuf[MAX_PATH];
    CHAR      szMsg[MAX_PATH];
    LPSTR     sPos;
    DWORD     retCode;
    BOOL      retValue;
    BOOL      serviceFlag = TRUE;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;    
    SERVICE_STATUS schSStatus;
    LPSTR     *args;
    int       ticks;

    if (ap_OSVersion == OS_VERSION_WIN9X)
    {
        sPos = strstr(szImagePath, "-k start");
        if (sPos)
        {
            lstrcpyn(szBuf, szImagePath, sPos - szImagePath);
            switch (dwCommand)
            {
            case SERVICE_CONTROL_STOP:
                lstrcat(szBuf, " -k stop -n ");
                break;
            case SERVICE_CONTROL_CONTINUE:
                sprintf(szMsg, "The %s is starting.", szServiceName);
                ListBox_SetCurSel(ap_hStdoutWnd,
                                   ListBox_AddString(ap_hStdoutWnd, szMsg));
                lstrcat(szBuf, " -k start -n ");
                serviceFlag = FALSE;
                break;
            case SERVICE_APACHE_RESTART:
                lstrcat(szBuf, " -k restart -n ");
                break;
            default:
                return FALSE;
            }
            lstrcat(szBuf, szServiceName);
        }
        else
            return FALSE;
        ap_consoleRun = TRUE;
        SetCursor(ap_cHourglass);
        if (!RunAndForgetConsole(szBuf, &retCode, serviceFlag))
        {
            ErrorMessage(retCode);
            ap_consoleRun = FALSE;
            SetCursor(ap_cArrow);
            return FALSE;
        }
        else if (!serviceFlag)
        {
            sprintf(szMsg, "The %s has started.", szServiceName);
            ListBox_SetCurSel(ap_hStdoutWnd,
                              ListBox_AddString(ap_hStdoutWnd, szMsg));

            ap_consoleRun = FALSE;
            SetCursor(ap_cArrow);
            return TRUE;
        }
    }
    else
    {
        /* Apache 2.0 uses '-k runservice' as cmdline parameter */
        sPos = strstr(szImagePath, "--ntservice");
        if (!sPos)
        {
            sPos = strstr(szImagePath, "-k runservice");
            serviceFlag = FALSE;
        }
        if (sPos)
            lstrcpyn(szBuf, szImagePath, sPos - szImagePath);
        else
            return FALSE;
        schSCManager = OpenSCManager(
            NULL,
            NULL,
            SC_MANAGER_ALL_ACCESS
           );
        if (!schSCManager)
            return FALSE;
        
        schService = OpenService(schSCManager, szServiceName, SERVICE_ALL_ACCESS);
        if (schService != NULL)
        {
            retValue = FALSE;
            ap_consoleRun = TRUE;
            SetCursor(ap_cHourglass);
            switch (dwCommand)
            {
                case SERVICE_CONTROL_STOP:
                    sprintf(szMsg, "The %s is stopping.", szServiceName);
                    ListBox_SetCurSel(ap_hStdoutWnd,
                                      ListBox_AddString(ap_hStdoutWnd, szMsg));
                    if(ControlService(schService, SERVICE_CONTROL_STOP, &schSStatus)) 
                    {
                        Sleep(1000);
                        while (QueryServiceStatus(schService, &schSStatus)) 
                        {
                            if (schSStatus.dwCurrentState == SERVICE_STOP_PENDING)
                                Sleep(1000);
                            else
                                break;
                        }
                    }
                    if (QueryServiceStatus(schService, &schSStatus))
                    {
                        if(schSStatus.dwCurrentState == SERVICE_STOPPED)
                        {
                            retValue = TRUE;
                            sprintf(szMsg, "The %s has stopped.", szServiceName);
                            ListBox_SetCurSel(ap_hStdoutWnd,
                                              ListBox_AddString(ap_hStdoutWnd, szMsg));
                        }
                    }
                break;                
                case SERVICE_CONTROL_CONTINUE:
                    sprintf(szMsg, "The %s is starting.", szServiceName);
                    ListBox_SetCurSel(ap_hStdoutWnd,
                                      ListBox_AddString(ap_hStdoutWnd, szMsg));
                    args = (char **)malloc(3 * sizeof(char*));
                    args[0] = szBuf;
                    if (serviceFlag)
                        args[1] = "--ntservice";
                    else
                    {
                        args[1] = "-k";
                        args[2] = "runservice";
                    }
                    if(StartService(schService, serviceFlag ? 2 : 3, args)) 
                    {
                        Sleep(1000);
                        while (QueryServiceStatus(schService, &schSStatus)) 
                        {
                            if (schSStatus.dwCurrentState == SERVICE_START_PENDING)
                                Sleep(1000);
                            else
                                break;
                        }
                    }
                    if (QueryServiceStatus(schService, &schSStatus))
                    {
                        if(schSStatus.dwCurrentState == SERVICE_RUNNING)
                        {
                            retValue = TRUE;
                            sprintf(szMsg, "The %s has started.", szServiceName);
                            ListBox_SetCurSel(ap_hStdoutWnd,
                                              ListBox_AddString(ap_hStdoutWnd, szMsg));
                        }
                    }
                    /* is this OK to do? */
                    free(args);
                break;                
                case SERVICE_APACHE_RESTART:
                    sprintf(szMsg, "The %s is restarting.", szServiceName);
                    ListBox_SetCurSel(ap_hStdoutWnd,
                                      ListBox_AddString(ap_hStdoutWnd, szMsg));
                    if(ControlService(schService, SERVICE_APACHE_RESTART, &schSStatus)) 
                    {
                        ticks = 60;
                        while(schSStatus.dwCurrentState == SERVICE_START_PENDING) 
                        {
                            Sleep(1000);
                            if(!QueryServiceStatus(schService, &schSStatus))
                            {
                                CloseServiceHandle(schService);
                                CloseServiceHandle(schSCManager);
                                ap_consoleRun = FALSE;
                                SetCursor(ap_cArrow);
                                return FALSE;
                            }
                            if (!--ticks)
                                break;
                        }
                    }
                    if(schSStatus.dwCurrentState == SERVICE_RUNNING)
                    {
                        retValue = TRUE;
                        sprintf(szMsg, "The %s has restarted.", szServiceName);
                        ListBox_SetCurSel(ap_hStdoutWnd,
                                          ListBox_AddString(ap_hStdoutWnd, szMsg));
                    }
                break;                
            }
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            if (!retValue)
                ErrorMessage(ERROR_SUCCESS);
            ap_consoleRun = FALSE;
            SetCursor(ap_cArrow);
            return retValue;
            
        }
        else
            ap_rescanServices = TRUE;
        
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
    
    return FALSE;
}

BOOL IsServiceRunning(LPCSTR szServiceName, LPDWORD lpdwPid)
{

    DWORD                   dwPid;
    HWND                    hWnd;
    SC_HANDLE               schService;
    SC_HANDLE               schSCManager;    
    SERVICE_STATUS          schSStatus;

    if (ap_OSVersion == OS_VERSION_WIN9X)
    {
        hWnd = FindWindow("ApacheWin95ServiceMonitor", szServiceName);
        if (hWnd && GetWindowThreadProcessId(hWnd, &dwPid))
        {
            *lpdwPid = 1;
            return TRUE;
        }
        else
            return FALSE;
    }
    else
    {

        dwPid = 0;
        schSCManager = OpenSCManager(
                            NULL,
                            NULL,
                            SC_MANAGER_ALL_ACCESS
                           );
        if (!schSCManager)
            return FALSE;

        schService = OpenService(schSCManager, szServiceName, SERVICE_QUERY_STATUS);
        if (schService != NULL)
        {
            if (QueryServiceStatus(schService, &schSStatus))
            {
                
                dwPid = schSStatus.dwCurrentState;
                if (lpdwPid)
                    *lpdwPid = 1;
            }
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return dwPid == SERVICE_RUNNING ? TRUE : FALSE;
        }
        else
            ap_rescanServices = TRUE;

        CloseServiceHandle(schSCManager);
        return FALSE;

    }

    return FALSE;
}

BOOL FindRunningServices()
{
    int i = 0;
    DWORD dwPid;
    BOOL rv = FALSE;
    while (ap_stServices[i].szServiceName != NULL)
    {    
        if (!IsServiceRunning(ap_stServices[i].szServiceName, &dwPid))
            dwPid = 0;
        if (ap_stServices[i].dwPid != dwPid)
            rv = TRUE;
        ap_stServices[i].dwPid = dwPid;
        ++i;
    }                        
    return rv;
}

BOOL GetApacheServicesStatus()
{

    CHAR    szKey[MAX_PATH];
    CHAR    achKey[MAX_PATH];
    CHAR    szImagePath[MAX_PATH];
    CHAR    szBuf[MAX_PATH];

    HKEY    hKey, hSubKey;
    DWORD   retCode, rv, dwKeyType;
    DWORD   dwBufLen = MAX_PATH;
    int     i, stPos = 0;

    ap_rescanServices = FALSE;

    retCode = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                            "System\\CurrentControlSet\\Services\\",
                            0, KEY_READ, &hKey);
    if (retCode != ERROR_SUCCESS)
    {
        ErrorMessage(retCode);
        return FALSE;
    }
    ap_ClearServicesSt();
    for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++)
    {

        retCode = RegEnumKey(hKey, i, achKey, MAX_PATH);
        if (retCode == ERROR_SUCCESS)
        {
            lstrcpy(szKey, "System\\CurrentControlSet\\Services\\");
            lstrcat(szKey, achKey);

            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szKey, 0, 
                KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
            {
                dwBufLen = MAX_PATH;
                rv = RegQueryValueEx(hSubKey, "ImagePath", NULL,
                                      &dwKeyType, szImagePath, &dwBufLen);

                if (rv == ERROR_SUCCESS && (dwKeyType == REG_SZ  || dwKeyType == REG_EXPAND_SZ) && dwBufLen)
                {
                    lstrcpy(szBuf, szImagePath);
                    CharLower(szBuf);
                    if (strstr(szBuf, "\\apache.exe") != NULL)
                    {
                        ap_stServices[stPos].szServiceName = strdup(achKey);
                        ap_stServices[stPos].szImagePath = strdup(szImagePath);
                        dwBufLen = MAX_PATH;
                        if (RegQueryValueEx(hSubKey, "Description", NULL,
                                      &dwKeyType, szBuf, &dwBufLen) == ERROR_SUCCESS)
                            ap_stServices[stPos].szDescription = strdup(szBuf);

                        dwBufLen = MAX_PATH;
                        if (RegQueryValueEx(hSubKey, "DisplayName", NULL,
                                      &dwKeyType, szBuf, &dwBufLen) == ERROR_SUCCESS)
                            ap_stServices[stPos].szDisplayName= strdup(szBuf);
                        ++stPos;
                        if (stPos >= MAX_APACHE_SERVICES)
                            retCode = !ERROR_SUCCESS;
                    }
                }
                RegCloseKey(hSubKey);
            }
        }
    }
    RegCloseKey(hKey);
    FindRunningServices();
    return TRUE;
}

LRESULT CALLBACK AboutDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    static  HFONT hfontDlg;    /* Font for dialog text */
    static  HFONT hFinePrint;  /* Font for 'fine print' in dialog */
    DWORD   dwVerInfoSize;     /* Size of version information block */
    LPSTR   lpVersion;         /* String pointer to 'version' text */
    DWORD   dwVerHnd=0;        /* An 'ignored' parameter, always '0' */
    UINT    uVersionLen;
    WORD    wRootLen;
    BOOL    bRetCode;
    int     i;
    char    szFullPath[256];
    char    szResult[256];
    char    szGetName[256];
    char    szVersion[256];
    DWORD   dwResult;
    
    switch (message) {
    case WM_INITDIALOG:
        ShowWindow(hDlg, SW_HIDE);
        ap_hwndAboutDlg = hDlg;
        
        hfontDlg = CreateFont(13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            VARIABLE_PITCH | FF_SWISS, "");
        hFinePrint = CreateFont(11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            VARIABLE_PITCH | FF_SWISS, "");

        CenterWindow(hDlg);
        GetModuleFileName(ap_hInstance, szFullPath, sizeof(szFullPath));
        
        /* Now lets dive in and pull out the version information: */
        dwVerInfoSize = GetFileVersionInfoSize(szFullPath, &dwVerHnd);
        if (dwVerInfoSize) {
            LPSTR   lpstrVffInfo;
            HANDLE  hMem;
            hMem = GlobalAlloc(GMEM_MOVEABLE, dwVerInfoSize);
            lpstrVffInfo  = GlobalLock(hMem);
            GetFileVersionInfo(szFullPath, dwVerHnd, dwVerInfoSize, lpstrVffInfo);
            lstrcpy(szGetName, GetStringRes(IDS_VER_INFO_LANG));
            
            wRootLen = lstrlen(szGetName); /* Save this position */
            
            /* Set the title of the dialog: */
            lstrcat(szGetName, "ProductName");
            bRetCode = VerQueryValue((LPVOID)lpstrVffInfo,
                (LPSTR)szGetName,
                (LPVOID)&lpVersion,
                (UINT *)&uVersionLen);
            
            /* Notice order of version and string... */
            lstrcpy(szResult, "About ");
            lstrcat(szResult, lpVersion);
            
            SetWindowText(hDlg, szResult);
            
            /* Walk through the dialog items that we want to replace: */
            for (i = DLG_VERFIRST; i <= DLG_VERLAST; i++) {
                GetDlgItemText(hDlg, i, szResult, sizeof(szResult));
                szGetName[wRootLen] = (char)0;
                lstrcat(szGetName, szResult);
                uVersionLen   = 0;
                lpVersion     = NULL;
                bRetCode      =  VerQueryValue((LPVOID)lpstrVffInfo,
                    (LPSTR)szGetName,
                    (LPVOID)&lpVersion,
                    (UINT *)&uVersionLen);
                
                if (bRetCode && uVersionLen && lpVersion) {
                    /* Replace dialog item text with version info */
                    lstrcpy(szResult, lpVersion);
                    SetDlgItemText(hDlg, i, szResult);
                }
                else
                {
                    dwResult = GetLastError();
                    
                    wsprintf(szResult, GetStringRes(IDS_VERSION_ERROR), dwResult);
                    SetDlgItemText(hDlg, i, szResult);
                }
                SendMessage(GetDlgItem(hDlg, i), WM_SETFONT,
                    (UINT)((i==DLG_VERLAST)?hFinePrint:hfontDlg),
                    TRUE);
            }
            
            
            GlobalUnlock(hMem);
            GlobalFree(hMem);
            
        } 
        
        SendMessage(GetDlgItem(hDlg, IDC_LABEL), WM_SETFONT,
            (WPARAM)hfontDlg,(LPARAM)TRUE);
        if (!GetSystemOSVersion(szVersion, NULL))
            strcpy(szVersion, "Unknown Version");
        SetWindowText(GetDlgItem(hDlg, IDC_OSVERSION), szVersion);
        ShowWindow(hDlg, SW_SHOW);
        return (TRUE);
        
      case WM_COMMAND:
          if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
              EndDialog(hDlg, TRUE);
              DeleteObject(hfontDlg);
              DeleteObject(hFinePrint);
              return (TRUE);
          }
          break;
   }
   
   return FALSE;
}

LRESULT CALLBACK ServiceDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

    CHAR        tchBuffer[MAX_PATH]; 
    CHAR        tsbBuffer[MAX_PATH];
    HWND        hListBox;
    static HWND hStatusBar; 
    TEXTMETRIC  tm; 
    int         i, y; 
    HDC         hdcMem; 
    RECT        rcBitmap; 
    UINT        nItem;
    LPMEASUREITEMSTRUCT lpmis; 
    LPDRAWITEMSTRUCT    lpdis; 

    ZeroMemory(tchBuffer, MAX_PATH);
    ZeroMemory(tsbBuffer, MAX_PATH);
    switch (message) 
    { 
 
        case WM_INITDIALOG: 
            ShowWindow(hDlg, SW_HIDE);
            ap_hServiceDlg = hDlg;
            hbmpStart = LoadBitmap(ap_hInstance, MAKEINTRESOURCE(IDB_BMPRUN)); 
            hbmpStop  = LoadBitmap(ap_hInstance, MAKEINTRESOURCE(IDB_BMPSTOP)); 

            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
            hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
            ap_hStdoutWnd = GetDlgItem(hDlg, IDL_STDOUT);
            hStatusBar = CreateStatusWindow(SBT_TOOLTIPS | WS_CHILD | WS_VISIBLE,
                                            "", hDlg, IDC_STATBAR);            
            if (GetApacheServicesStatus())
            {
                i = 0;
                while (ap_stServices[i].szServiceName != NULL)
                {    
                    addItem(hListBox, ap_stServices[i].szDisplayName, 
                        ap_stServices[i].dwPid == 0 ? hbmpStop : hbmpStart);
                    ++i;
                }
            }
            CenterWindow(hDlg);
            ShowWindow(hDlg, SW_SHOW);
            SetFocus(hListBox); 
            SendMessage(hListBox, LB_SETCURSEL, 0, 0); 
            return TRUE;
        break;
        case WM_UPDATEMESSAGE:
            hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
            SendMessage(hListBox, LB_RESETCONTENT, 0, 0); 
            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
            i = 0;
            while (ap_stServices[i].szServiceName != NULL)
            {    
                addItem(hListBox, ap_stServices[i].szDisplayName, 
                    ap_stServices[i].dwPid == 0 ? hbmpStop : hbmpStart);
                ++i;
            }
            SendMessage(hListBox, LB_SETCURSEL, 0, 0); 
            /* Dirty hack to bring the window to the foreground */
            SetWindowPos(hDlg, HWND_TOPMOST, 0, 0, 0, 0,
                                    SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
            SetWindowPos(hDlg, HWND_NOTOPMOST, 0, 0, 0, 0,
                                    SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
            SetFocus(hListBox); 
            return TRUE;
        break;
        case WM_MEASUREITEM: 
 
            lpmis = (LPMEASUREITEMSTRUCT) lParam; 
            lpmis->itemHeight = 16; 
            return TRUE; 
        case WM_SETCURSOR:
            if (ap_consoleRun)
                SetCursor(ap_cHourglass);
            else
                SetCursor(ap_cArrow);
            return TRUE;
        case WM_DRAWITEM: 
 
            lpdis = (LPDRAWITEMSTRUCT) lParam; 
            if (lpdis->itemID == -1) 
            { 
                break; 
            } 
            switch (lpdis->itemAction) 
            { 
                case ODA_SELECT: 
                case ODA_DRAWENTIRE: 
                    hbmpPicture = (HBITMAP)SendMessage(lpdis->hwndItem, 
                        LB_GETITEMDATA, lpdis->itemID, (LPARAM) 0); 
 
                    hdcMem = CreateCompatibleDC(lpdis->hDC); 
                    hbmpOld = SelectObject(hdcMem, hbmpPicture); 
 
                    BitBlt(lpdis->hDC, 
                        lpdis->rcItem.left, lpdis->rcItem.top, 
                        lpdis->rcItem.right - lpdis->rcItem.left, 
                        lpdis->rcItem.bottom - lpdis->rcItem.top, 
                        hdcMem, 0, 0, SRCCOPY); 
                    SendMessage(lpdis->hwndItem, LB_GETTEXT, 
                        lpdis->itemID, (LPARAM) tchBuffer); 
 
                    GetTextMetrics(lpdis->hDC, &tm);  
                    y = (lpdis->rcItem.bottom + lpdis->rcItem.top - 
                        tm.tmHeight) / 2; 
  
                    SelectObject(hdcMem, hbmpOld); 
                    DeleteDC(hdcMem); 
 
                    rcBitmap.left = lpdis->rcItem.left + XBITMAP + 2; 
                    rcBitmap.top = lpdis->rcItem.top; 
                    rcBitmap.right = lpdis->rcItem.right; 
                    rcBitmap.bottom = lpdis->rcItem.top + YBITMAP; 

                    if (lpdis->itemState & ODS_SELECTED) 
                    { 
                        if (hbmpPicture == hbmpStop)
                        {
                            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), TRUE);
                            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                        }
                        else if (hbmpPicture == hbmpStart) 
                        {
                            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), TRUE);
                            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), TRUE);
                        }
                        if (ap_stServices[lpdis->itemID].szDescription)
                            lstrcpy(tsbBuffer, ap_stServices[lpdis->itemID].szDescription); 
                        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)tsbBuffer);
                        
                        SetTextColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHTTEXT)); 
                        SetBkColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHT)); 
                        FillRect(lpdis->hDC, &rcBitmap, (HBRUSH)(COLOR_HIGHLIGHTTEXT)); 
                    } 
                    else
                    {
                       SetTextColor(lpdis->hDC, GetSysColor(COLOR_MENUTEXT)); 
                       SetBkColor(lpdis->hDC, GetSysColor(COLOR_WINDOW)); 
                       FillRect(lpdis->hDC, &rcBitmap, (HBRUSH)(COLOR_WINDOW+1)); 
                    }
                    TextOut(lpdis->hDC, 
                        XBITMAP + 6, 
                        y, 
                        tchBuffer, 
                        strlen(tchBuffer)); 
                    break; 
 
                case ODA_FOCUS: 
                    break; 
            } 
            return TRUE;  
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
                case IDL_SERVICES:
                    switch (HIWORD(wParam))
                    {
                        case LBN_DBLCLK:
                            /* if started then stop, if stopped the start the service */
                            hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
                            nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0); 
                            if (nItem != LB_ERR)
                            {
                                hbmpPicture = (HBITMAP)SendMessage(hListBox, LB_GETITEMDATA,
                                                               nItem, (LPARAM) 0); 
                                if (hbmpPicture == hbmpStop)
                                {
                                    ApacheManageService(ap_stServices[nItem].szServiceName,
                                                ap_stServices[nItem].szImagePath,
                                                SERVICE_CONTROL_CONTINUE);
                                }
                                else
                                    ApacheManageService(ap_stServices[nItem].szServiceName,
                                                ap_stServices[nItem].szImagePath,
                                                SERVICE_CONTROL_STOP);

                            }
                            return TRUE;
                        break;
                     }
                break;
                case IDOK: 
                    EndDialog(hDlg, TRUE); 
                    return TRUE; 
                break;
                case IDC_SSTART: 
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                    hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
                    nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0); 
                    if (nItem != LB_ERR)
                    {
                        ApacheManageService(ap_stServices[nItem].szServiceName,
                                             ap_stServices[nItem].szImagePath,
                                             SERVICE_CONTROL_CONTINUE);
                    }
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), TRUE);
                    return TRUE;
                break;
                case IDC_SSTOP: 
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                    hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
                    nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0); 
                    if (nItem != LB_ERR)
                    {
                        ApacheManageService(ap_stServices[nItem].szServiceName,
                                             ap_stServices[nItem].szImagePath,
                                             SERVICE_CONTROL_STOP);
                    }
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), TRUE);
                    return TRUE;
                break;
                case IDC_SRESTART: 
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                    hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
                    nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0); 
                    if (nItem != LB_ERR)
                    {
                        ApacheManageService(ap_stServices[nItem].szServiceName,
                                             ap_stServices[nItem].szImagePath,
                                             SERVICE_APACHE_RESTART);
                    }
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), TRUE);
                    return TRUE;
                break;
                case IDC_SABOUT: 
                   if (!dlgAboutOn)
                   {
                      dlgAboutOn = TRUE;
                      DialogBox(ap_hInstance, MAKEINTRESOURCE(IDD_ABOUTBOX),
                             ap_hMainWnd, (DLGPROC)AboutDlgProc);
                      dlgAboutOn = FALSE;
                      ap_hwndAboutDlg = NULL;                      
                   }
                   else if (ap_hwndAboutDlg)
                       SetFocus(ap_hwndAboutDlg);
                    return TRUE;
                break;
             }
        break;
        case WM_SIZE:
            switch (LOWORD(wParam)) 
            { 
                case SIZE_MINIMIZED:
                    EndDialog(hDlg, TRUE); 
                    return TRUE; 
                break;
            }
        break;
        case WM_CLOSE: 
            EndDialog(hDlg, TRUE);
            return TRUE;
        case WM_DESTROY: 
            DeleteObject(hbmpStart); 
            DeleteObject(hbmpStop); 
            return TRUE; 
        default:
            return FALSE;
    }
    return FALSE;
}


VOID CALLBACK MainTimerProc(HWND hWnd, UINT uMsg, UINT idEvent, DWORD dwTime)
{
    int nPrev = 0, nNew = 0;
    if (idEvent == WM_TIMER_RESCAN)
    {
        if (FindRunningServices() || ap_rescanServices)
        {
            ShowNotifyIcon(hWnd, NIM_MODIFY);
            if (ap_hServiceDlg)
                PostMessage(ap_hServiceDlg, WM_UPDATEMESSAGE, 0, 0);
        }
        /* check if services list changed */
        while (ap_stServices[nPrev].szServiceName != NULL)
            ++nPrev;
        GetApacheServicesStatus();
        while (ap_stServices[nNew].szServiceName != NULL)
            ++nNew;
        if (nPrev != nNew)
        {
            ShowNotifyIcon(hWnd, NIM_MODIFY);
            if (ap_hServiceDlg)
                PostMessage(ap_hServiceDlg, WM_UPDATEMESSAGE, 0, 0);
        }
    }
    else if (idEvent == WM_TIMER_REFRESH)
    {
        if (ap_rescanServices)
        {
            GetApacheServicesStatus();
            ShowNotifyIcon(hWnd, NIM_MODIFY);
            if (ap_hServiceDlg)
                PostMessage(ap_hServiceDlg, WM_UPDATEMESSAGE, 0, 0);
        }
        else if (FindRunningServices())
        {
            ShowNotifyIcon(hWnd, NIM_MODIFY);
            if (ap_hServiceDlg)
                PostMessage(ap_hServiceDlg, WM_UPDATEMESSAGE, 0, 0);
        }
    }
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message,
                          WPARAM wParam, LPARAM lParam)
{
    
    if (message == ap_uiTaskbarCreated)
    {
        /* restore the tray icon on shell restart */
        ShowNotifyIcon(hWnd, NIM_ADD);
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    switch (message) 
    {
        case WM_CREATE:
            GetSystemOSVersion(NULL, &ap_OSVersion);
            GetApacheServicesStatus();
            ShowNotifyIcon(hWnd, NIM_ADD);
            SetTimer(hWnd, WM_TIMER_REFRESH, REFRESH_TIME, (TIMERPROC)MainTimerProc);
            SetTimer(hWnd, WM_TIMER_RESCAN,  RESCAN_TIME, (TIMERPROC)MainTimerProc);
            ap_hServiceDlg = NULL;                      
        break;
        case WM_QUIT:
            ShowNotifyIcon(hWnd, NIM_DELETE);
        break;
        case WM_TRAYMESSAGE:
            switch(lParam)
            {
                case WM_LBUTTONDBLCLK:
                   if (!dlgServiceOn)
                   {
                       dlgServiceOn = TRUE;
                       DialogBox(ap_hInstance, MAKEINTRESOURCE(IDD_APSRVMON_DIALOG),
                             hWnd, (DLGPROC)ServiceDlgProc);
                       dlgServiceOn = FALSE;
                       ap_hServiceDlg = NULL;
                   }
                   else if (ap_hServiceDlg)
                   {
                       /* Dirty hack to bring the window to the foreground */
                       SetWindowPos(ap_hServiceDlg, HWND_TOPMOST, 0, 0, 0, 0,
                                    SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
                       SetWindowPos(ap_hServiceDlg, HWND_NOTOPMOST, 0, 0, 0, 0,
                                    SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
                       SetFocus(ap_hServiceDlg);
                   }
                break;
                case WM_RBUTTONUP:
                    ShowTryPopupMenu(hWnd);
                break;    
            }
            break;
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
               case IDM_RESTORE:
                   if (!dlgServiceOn)
                   {
                       dlgServiceOn = TRUE;
                       DialogBox(ap_hInstance, MAKEINTRESOURCE(IDD_APSRVMON_DIALOG),
                             hWnd, (DLGPROC)ServiceDlgProc);
                       dlgServiceOn = FALSE;
                       ap_hServiceDlg = NULL;
                   }
                   else if (ap_hServiceDlg)
                       SetFocus(ap_hServiceDlg);
               break;
               case IDM_ABOUT:
                   if (!dlgAboutOn)
                   {
                      dlgAboutOn = TRUE;
                      DialogBox(ap_hInstance, MAKEINTRESOURCE(IDD_ABOUTBOX),
                             hWnd, (DLGPROC)AboutDlgProc);
                      dlgAboutOn = FALSE;
                      ap_hwndAboutDlg = NULL;                      
                   }
                   else if (ap_hwndAboutDlg)
                       SetFocus(ap_hwndAboutDlg);
                break;
                case IDM_EXIT:
                    PostQuitMessage(0);
                    return TRUE;
                break;
            }
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return FALSE;
}

/* Create main invisible window */
HWND CreateMainWindow(HINSTANCE hInstance)
{
    HWND       hWnd = NULL;
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX); 

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = (WNDPROC)WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, (LPCTSTR)IDI_APSRVMON);
    wcex.hCursor        = ap_cArrow;
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = (LPCSTR)IDC_APSRVMON;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, (LPCTSTR)IDI_APSMALL);

    if (RegisterClassEx(&wcex))
    {
        hWnd = CreateWindow(szWindowClass, szTitle,
                             0, 0, 0, 0, 0,
                             NULL, NULL, hInstance, NULL);
    }

    return hWnd;

}


int WINAPI WinMain(HINSTANCE hInstance,
                    HINSTANCE hPrevInstance,
                    LPTSTR lpCmdLine,
                    int nCmdShow)
{
    MSG     msg;
    /* single instance mutex */
    HANDLE hMutex = CreateMutex(NULL, FALSE, "APSRVMON_MUTEX");
    if((hMutex == NULL) || (GetLastError() == ERROR_ALREADY_EXISTS))
    {
        if (hMutex)
            CloseHandle(hMutex);

        return 0;
    }
    InitCommonControls();
    ap_hInstance = hInstance;

    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadString(hInstance, IDC_APSRVMON,  szWindowClass, MAX_LOADSTRING);
    ap_icoStop  = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICOSTOP));
    ap_icoRun   = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICORUN));
    ap_cHourglass = LoadCursor(NULL, IDC_WAIT);
    ap_cArrow     = LoadCursor(NULL, IDC_ARROW);

    ZeroMemory(ap_stServices, sizeof(ST_APACHE_SERVICE) * MAX_APACHE_SERVICES);
    ap_hMainWnd = CreateMainWindow(hInstance);
    if (ap_hMainWnd != NULL)
    {
        ap_uiTaskbarCreated = RegisterWindowMessage("TaskbarCreated");
        while (GetMessage(&msg, NULL, 0, 0) == TRUE) 
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }    
        ap_ClearServicesSt();
    }
    CloseHandle(hMutex);
    return 0;
}
