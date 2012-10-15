/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* ====================================================================
 * ApacheMonitor.c Simple program to manage and monitor Apache services.
 *
 * Contributed by Mladen Turk <mturk mappingsoft.com>
 *
 * 05 Aug 2001
 * ====================================================================
 */

#define _WIN32_WINNT 0x0500
#ifndef STRICT
#define STRICT
#endif
#ifndef OEMRESOURCE
#define OEMRESOURCE
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1400
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdlib.h>
#include <stdio.h>
#include <WtsApi32.h>
#include <tchar.h>
#include "ApacheMonitor.h"

#ifndef AM_STRINGIFY
/** Properly quote a value as a string in the C preprocessor */
#define AM_STRINGIFY(n) AM_STRINGIFY_HELPER(n)
/** Helper macro for AM_STRINGIFY */
#define AM_STRINGIFY_HELPER(n) #n
#endif

#define OS_VERSION_WINNT    2
#define OS_VERSION_WIN2K    3

/* Should be enough */
#define MAX_APACHE_SERVICES 128
#define MAX_APACHE_COMPUTERS 32

#define WM_TRAYMESSAGE         (WM_APP+1)
#define WM_UPDATEMESSAGE       (WM_USER+1)
#define WM_MANAGEMESSAGE       (WM_USER+2)
#define WM_TIMER_REFRESH       10
#define WM_TIMER_RESCAN        11
#define SERVICE_APACHE_RESTART 128
#define XBITMAP                16
#define YBITMAP                16
#define MAX_LOADSTRING         100
#define REFRESH_TIME           2000           /* service refresh time (ms) */
#define RESCAN_TIME            20000          /* registry rescan time (ms) */

typedef struct _st_APACHE_SERVICE
{
    LPTSTR   szServiceName;
    LPTSTR   szDisplayName;
    LPTSTR   szDescription;
    LPTSTR   szImagePath;
    LPTSTR   szComputerName;
    DWORD    dwPid;
} ST_APACHE_SERVICE;

typedef struct _st_MONITORED_COMPUTERS
{
    LPTSTR  szComputerName;
    HKEY    hRegistry;
} ST_MONITORED_COMP;

/* Global variables */
HINSTANCE         g_hInstance = NULL;
TCHAR            *g_szTitle;          /* The title bar text */
TCHAR            *g_szWindowClass;    /* Window Class Name  */
HICON             g_icoStop;
HICON             g_icoRun;
UINT              g_bUiTaskbarCreated;
DWORD             g_dwOSVersion;
BOOL              g_bDlgServiceOn = FALSE;
BOOL              g_bConsoleRun = FALSE;
ST_APACHE_SERVICE g_stServices[MAX_APACHE_SERVICES];
ST_MONITORED_COMP g_stComputers[MAX_APACHE_COMPUTERS];

HBITMAP           g_hBmpStart, g_hBmpStop;
HBITMAP           g_hBmpPicture, g_hBmpOld;
BOOL              g_bRescanServices;
HWND              g_hwndServiceDlg;
HWND              g_hwndMain;
HWND              g_hwndStdoutList;
HWND              g_hwndConnectDlg;
HCURSOR           g_hCursorHourglass;
HCURSOR           g_hCursorArrow;

LANGID            g_LangID;
CRITICAL_SECTION  g_stcSection;
LPTSTR            g_szLocalHost;

/* locale language support */
static TCHAR *g_lpMsg[IDS_MSG_LAST - IDS_MSG_FIRST + 1];


void am_ClearServicesSt()
{
    int i;
    for (i = 0; i < MAX_APACHE_SERVICES; i++)
    {
        if (g_stServices[i].szServiceName) {
            free(g_stServices[i].szServiceName);
        }
        if (g_stServices[i].szDisplayName) {
            free(g_stServices[i].szDisplayName);
        }
        if (g_stServices[i].szDescription) {
            free(g_stServices[i].szDescription);
        }
        if (g_stServices[i].szImagePath) {
            free(g_stServices[i].szImagePath);
        }
        if (g_stServices[i].szComputerName) {
            free(g_stServices[i].szComputerName);
        }

    }
    memset(g_stServices, 0, sizeof(ST_APACHE_SERVICE) * MAX_APACHE_SERVICES);

}


void am_ClearComputersSt()
{
    int i;
    for (i = 0; i < MAX_APACHE_COMPUTERS; i++) {
        if (g_stComputers[i].szComputerName) {
            free(g_stComputers[i].szComputerName);
            RegCloseKey(g_stComputers[i].hRegistry);
        }
    }
    memset(g_stComputers, 0, sizeof(ST_MONITORED_COMP) * MAX_APACHE_COMPUTERS);

}


BOOL am_IsComputerConnected(LPTSTR szComputerName)
{
    int i = 0;
    while (g_stComputers[i].szComputerName != NULL) {
        if (_tcscmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            return TRUE;
        }
        ++i;
    }
    return FALSE;
}


void am_DisconnectComputer(LPTSTR szComputerName)
{
    int i = 0, j;
    while (g_stComputers[i].szComputerName != NULL) {
        if (_tcscmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            break;
        }
        ++i;
    }
    if (g_stComputers[i].szComputerName != NULL) {
        free(g_stComputers[i].szComputerName);
        RegCloseKey(g_stComputers[i].hRegistry);
        for (j = i; j < MAX_APACHE_COMPUTERS - 1; j++) {
            g_stComputers[j].szComputerName= g_stComputers[j+1].szComputerName;
            g_stComputers[j].hRegistry = g_stComputers[j+1].hRegistry;
        }
        g_stComputers[j].szComputerName = NULL;
        g_stComputers[j].hRegistry = NULL;
    }
}


void ErrorMessage(LPCTSTR szError, BOOL bFatal)
{
    LPVOID lpMsgBuf = NULL;
    if (szError) {
        MessageBox(NULL, szError, g_lpMsg[IDS_MSG_ERROR - IDS_MSG_FIRST],
                   MB_OK | (bFatal ? MB_ICONERROR : MB_ICONEXCLAMATION));
    }
    else {
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, GetLastError(), g_LangID,
                      (LPTSTR) &lpMsgBuf, 0, NULL);
        MessageBox(NULL, (LPCTSTR)lpMsgBuf,
                   g_lpMsg[IDS_MSG_ERROR - IDS_MSG_FIRST],
                   MB_OK | (bFatal ? MB_ICONERROR : MB_ICONEXCLAMATION));
        LocalFree(lpMsgBuf);
    }
    if (bFatal) {
        PostQuitMessage(0);
    }
}


int am_RespawnAsUserAdmin(HWND hwnd, DWORD op, LPCTSTR szService,
                          LPCTSTR szComputerName)
{
    TCHAR args[MAX_PATH + MAX_COMPUTERNAME_LENGTH + 12];

    if (g_dwOSVersion < OS_VERSION_WIN2K) {
        ErrorMessage(g_lpMsg[IDS_MSG_SRVFAILED - IDS_MSG_FIRST], FALSE);
        return 0;
    }

    _sntprintf(args, sizeof(args) / sizeof(TCHAR),
               _T("%d \"%s\" \"%s\""), op, szService,
               szComputerName ? szComputerName : _T(""));
    if (!ShellExecute(hwnd, _T("runas"), __targv[0], args, NULL, SW_NORMAL)) {
        ErrorMessage(g_lpMsg[IDS_MSG_SRVFAILED - IDS_MSG_FIRST],
                     FALSE);
        return 0;
    }

    return 1;
}


BOOL am_ConnectComputer(LPTSTR szComputerName)
{
    int i = 0;
    HKEY hKeyRemote;
    TCHAR szTmp[MAX_PATH];

    while (g_stComputers[i].szComputerName != NULL) {
        if (_tcscmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            return FALSE;
        }
        ++i;
    }
    if (i > MAX_APACHE_COMPUTERS - 1) {
        return FALSE;
    }
    if (RegConnectRegistry(szComputerName, HKEY_LOCAL_MACHINE, &hKeyRemote)
            != ERROR_SUCCESS) {
        _sntprintf(szTmp, sizeof(szTmp) / sizeof(TCHAR),
                   g_lpMsg[IDS_MSG_ECONNECT - IDS_MSG_FIRST],
                   szComputerName);
        ErrorMessage(szTmp, FALSE);
        return FALSE;
    }
    else {
        g_stComputers[i].szComputerName = _tcsdup(szComputerName);
        g_stComputers[i].hRegistry = hKeyRemote;
        return TRUE;
    }
}


LPTSTR GetStringRes(int id)
{
    static TCHAR buffer[MAX_PATH];

    buffer[0] = 0;
    LoadString(GetModuleHandle(NULL), id, buffer, MAX_PATH);
    return buffer;
}


BOOL GetSystemOSVersion(LPDWORD dwVersion)
{
    OSVERSIONINFO osvi;
    /*
    Try calling GetVersionEx using the OSVERSIONINFOEX structure.
    If that fails, try using the OSVERSIONINFO structure.
    */
    memset(&osvi, 0, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (!GetVersionEx(&osvi)) {
        return FALSE;
    }

    switch (osvi.dwPlatformId)
    {
    case VER_PLATFORM_WIN32_NT:
        if (osvi.dwMajorVersion >= 5)
            *dwVersion = OS_VERSION_WIN2K;
        else
            *dwVersion = OS_VERSION_WINNT;
        break;

    case VER_PLATFORM_WIN32_WINDOWS:
    case VER_PLATFORM_WIN32s:
    default:
        *dwVersion = 0;
        return FALSE;
    }
    return TRUE;
}


static VOID ShowNotifyIcon(HWND hWnd, DWORD dwMessage)
{
    NOTIFYICONDATA nid;
    int i = 0, n = 0;

    memset(&nid, 0, sizeof(nid));
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = hWnd;
    nid.uID = 0xFF;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYMESSAGE;

    while (g_stServices[i].szServiceName != NULL)
    {
        if (g_stServices[i].dwPid != 0) {
            ++n;
        }
        ++i;
    }
    if (dwMessage != NIM_DELETE)
    {
        if (n) {
            nid.hIcon = g_icoRun;
        }
        else {
            nid.hIcon = g_icoStop;
        }
    }
    else {
        nid.hIcon = NULL;
    }
    if (n == i && n > 0) {
        _tcscpy(nid.szTip, g_lpMsg[IDS_MSG_RUNNINGALL - IDS_MSG_FIRST]);
    }
    else if (n) {
        _sntprintf(nid.szTip, sizeof(nid.szTip) / sizeof(TCHAR),
                  g_lpMsg[IDS_MSG_RUNNING - IDS_MSG_FIRST], n, i);
    }
    else if (i) {
        _sntprintf(nid.szTip, sizeof(nid.szTip) / sizeof(TCHAR),
                  g_lpMsg[IDS_MSG_RUNNINGNONE - IDS_MSG_FIRST], i);
    }
    else {
        _tcscpy(nid.szTip, g_lpMsg[IDS_MSG_NOSERVICES - IDS_MSG_FIRST]);
    }
    Shell_NotifyIcon(dwMessage, &nid);
}


void appendMenuItem(HMENU hMenu, UINT uMenuId, LPTSTR szName,
                    BOOL fDefault, BOOL fEnabled)
{
    MENUITEMINFO mii;

    memset(&mii, 0, sizeof(MENUITEMINFO));
    mii.cbSize = sizeof(MENUITEMINFO);
    mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE;
    if (_tcslen(szName))
    {
        mii.fType = MFT_STRING;
        mii.wID = uMenuId;
        if (fDefault) {
            mii.fState = MFS_DEFAULT;
        }
        if (!fEnabled) {
            mii.fState |= MFS_DISABLED;
        }
        mii.dwTypeData = szName;
    }
    else {
        mii.fType = MFT_SEPARATOR;
    }
    InsertMenuItem(hMenu, uMenuId, FALSE, &mii);
}


void appendServiceMenu(HMENU hMenu, UINT uMenuId,
                       LPTSTR szServiceName, BOOL fRunning)
{
    MENUITEMINFO mii;
    HMENU smh;

    smh = CreatePopupMenu();

    appendMenuItem(smh, IDM_SM_START + uMenuId,
                   g_lpMsg[IDS_MSG_SSTART - IDS_MSG_FIRST], FALSE, !fRunning);
    appendMenuItem(smh, IDM_SM_STOP + uMenuId,
                   g_lpMsg[IDS_MSG_SSTOP - IDS_MSG_FIRST], FALSE, fRunning);
    appendMenuItem(smh, IDM_SM_RESTART + uMenuId,
                   g_lpMsg[IDS_MSG_SRESTART - IDS_MSG_FIRST], FALSE, fRunning);

    memset(&mii, 0, sizeof(MENUITEMINFO));
    mii.cbSize = sizeof(MENUITEMINFO);
    mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE | MIIM_SUBMENU
              | MIIM_CHECKMARKS;
    mii.fType = MFT_STRING;
    mii.wID = uMenuId;
    mii.hbmpChecked = g_hBmpStart;
    mii.hbmpUnchecked = g_hBmpStop;
    mii.dwTypeData = szServiceName;
    mii.hSubMenu = smh;
    mii.fState = fRunning ? MFS_CHECKED : MFS_UNCHECKED;
    InsertMenuItem(hMenu, IDM_SM_SERVICE + uMenuId, FALSE, &mii);
}


void ShowTryPopupMenu(HWND hWnd)
{
    /* create popup menu */
    HMENU hMenu = CreatePopupMenu();
    POINT pt;

    if (hMenu)
    {
        appendMenuItem(hMenu, IDM_RESTORE,
                       g_lpMsg[IDS_MSG_MNUSHOW - IDS_MSG_FIRST],
                       TRUE, TRUE);
        appendMenuItem(hMenu, IDC_SMANAGER,
                       g_lpMsg[IDS_MSG_MNUSERVICES - IDS_MSG_FIRST],
                       FALSE, TRUE);
        appendMenuItem(hMenu, 0, _T(""), FALSE, TRUE);
        appendMenuItem(hMenu, IDM_EXIT,
                       g_lpMsg[IDS_MSG_MNUEXIT - IDS_MSG_FIRST],
                       FALSE, TRUE);

        if (!SetForegroundWindow(hWnd)) {
            SetForegroundWindow(NULL);
        }
        GetCursorPos(&pt);
        TrackPopupMenu(hMenu, TPM_LEFTALIGN|TPM_RIGHTBUTTON,
                       pt.x, pt.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);
    }
}


void ShowTryServicesMenu(HWND hWnd)
{
    /* create services list popup menu and submenus */
    HMENU hMenu = CreatePopupMenu();
    POINT pt;
    int i = 0;

    if (hMenu)
    {
        while (g_stServices[i].szServiceName != NULL)
        {
            appendServiceMenu(hMenu, i, g_stServices[i].szDisplayName,
                              g_stServices[i].dwPid != 0);
            ++i;
        }
        if (i)
        {
            if (!SetForegroundWindow(hWnd)) {
                SetForegroundWindow(NULL);
            }
            GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_LEFTALIGN|TPM_RIGHTBUTTON,
                           pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
        }
    }
}


BOOL CenterWindow(HWND hwndChild)
{
   RECT rChild, rWorkArea;
   int wChild, hChild;
   int xNew, yNew;
   BOOL bResult;

   /* Get the Height and Width of the child window */
   GetWindowRect(hwndChild, &rChild);
   wChild = rChild.right - rChild.left;
   hChild = rChild.bottom - rChild.top;

   /* Get the limits of the 'workarea' */
   bResult = SystemParametersInfo(SPI_GETWORKAREA, sizeof(RECT),
                                  &rWorkArea, 0);
   if (!bResult) {
      rWorkArea.left = rWorkArea.top = 0;
      rWorkArea.right = GetSystemMetrics(SM_CXSCREEN);
      rWorkArea.bottom = GetSystemMetrics(SM_CYSCREEN);
   }

   /* Calculate new X and Y position*/
   xNew = (rWorkArea.right - wChild) / 2;
   yNew = (rWorkArea.bottom - hChild) / 2;
   return SetWindowPos(hwndChild, HWND_TOP, xNew, yNew, 0, 0,
                       SWP_NOSIZE | SWP_SHOWWINDOW);
}


static void addListBoxItem(HWND hDlg, LPTSTR lpStr, HBITMAP hBmp)
{
    LRESULT nItem;

    nItem = SendMessage(hDlg, LB_ADDSTRING, 0, (LPARAM)lpStr);
    SendMessage(hDlg, LB_SETITEMDATA, nItem, (LPARAM)hBmp);
}


static void addListBoxString(HWND hListBox, LPTSTR lpStr)
{
    static int nItems = 0;
    if (!g_bDlgServiceOn) {
        return;
    }
    ++nItems;
    if (nItems > MAX_LOADSTRING)
    {
        SendMessage(hListBox, LB_RESETCONTENT, 0, 0);
        nItems = 1;
    }
    ListBox_SetCurSel(hListBox,
                      ListBox_AddString(hListBox, lpStr));

}


BOOL ApacheManageService(LPCTSTR szServiceName, LPCTSTR szImagePath,
                         LPTSTR szComputerName, DWORD dwCommand)
{
    TCHAR szMsg[MAX_PATH];
    BOOL retValue;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;
    SERVICE_STATUS schSStatus;
    int ticks;

    schSCManager = OpenSCManager(szComputerName, NULL,
                                 SC_MANAGER_CONNECT);
    if (!schSCManager) {
        ErrorMessage(g_lpMsg[IDS_MSG_SRVFAILED - IDS_MSG_FIRST],
                     FALSE);
        return FALSE;
    }

    schService = OpenService(schSCManager, szServiceName,
                             SERVICE_QUERY_STATUS | SERVICE_START |
                             SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL);
    if (schService == NULL)
    {
        /* Avoid recursion of ImagePath NULL (from this Respawn) */
        if (szImagePath) {
            am_RespawnAsUserAdmin(g_hwndMain, dwCommand,
                                  szServiceName, szComputerName);
        }
        else {
            ErrorMessage(g_lpMsg[IDS_MSG_SRVFAILED - IDS_MSG_FIRST],
                         FALSE);
        }
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
    else
    {
        retValue = FALSE;
        g_bConsoleRun = TRUE;
        SetCursor(g_hCursorHourglass);
        switch (dwCommand)
        {
          case SERVICE_CONTROL_STOP:
            _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                       g_lpMsg[IDS_MSG_SRVSTOP - IDS_MSG_FIRST],
                       szServiceName);
            addListBoxString(g_hwndStdoutList, szMsg);
            if (ControlService(schService, SERVICE_CONTROL_STOP,
                               &schSStatus)) {
                Sleep(1000);
                while (QueryServiceStatus(schService, &schSStatus))
                {
                    if (schSStatus.dwCurrentState == SERVICE_STOP_PENDING)
                    {
                        Sleep(1000);
                    }
                    else {
                        break;
                    }
                }
            }
            if (QueryServiceStatus(schService, &schSStatus))
            {
                if (schSStatus.dwCurrentState == SERVICE_STOPPED)
                {
                    retValue = TRUE;
                    _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                               g_lpMsg[IDS_MSG_SRVSTOPPED - IDS_MSG_FIRST],
                               szServiceName);
                    addListBoxString(g_hwndStdoutList, szMsg);
                }
            }
            break;

          case SERVICE_CONTROL_CONTINUE:
            _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                       g_lpMsg[IDS_MSG_SRVSTART - IDS_MSG_FIRST],
                       szServiceName);
            addListBoxString(g_hwndStdoutList, szMsg);

            if (StartService(schService, 0, NULL))
            {
                Sleep(1000);
                while (QueryServiceStatus(schService, &schSStatus))
                {
                    if (schSStatus.dwCurrentState == SERVICE_START_PENDING)
                    {
                        Sleep(1000);
                    }
                    else {
                        break;
                    }
                }
            }
            if (QueryServiceStatus(schService, &schSStatus))
            {
                if (schSStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    retValue = TRUE;
                    _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                               g_lpMsg[IDS_MSG_SRVSTARTED - IDS_MSG_FIRST],
                               szServiceName);
                    addListBoxString(g_hwndStdoutList, szMsg);
                }
            }
            break;

          case SERVICE_APACHE_RESTART:
            _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                       g_lpMsg[IDS_MSG_SRVRESTART - IDS_MSG_FIRST],
                       szServiceName);
            addListBoxString(g_hwndStdoutList, szMsg);
            if (ControlService(schService, SERVICE_APACHE_RESTART,
                               &schSStatus))
            {
                ticks = 60;
                while (schSStatus.dwCurrentState == SERVICE_START_PENDING)
                {
                    Sleep(1000);
                    if (!QueryServiceStatus(schService, &schSStatus))
                    {
                        CloseServiceHandle(schService);
                        CloseServiceHandle(schSCManager);
                        g_bConsoleRun = FALSE;
                        SetCursor(g_hCursorArrow);
                        return FALSE;
                    }
                    if (!--ticks) {
                        break;
                    }
                }
            }
            if (schSStatus.dwCurrentState == SERVICE_RUNNING)
            {
                retValue = TRUE;
                _sntprintf(szMsg, sizeof(szMsg) / sizeof(TCHAR),
                           g_lpMsg[IDS_MSG_SRVRESTARTED - IDS_MSG_FIRST],
                           szServiceName);
                addListBoxString(g_hwndStdoutList, szMsg);
            }
            break;
        }
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        if (!retValue) {
            ErrorMessage(g_lpMsg[IDS_MSG_SRVFAILED - IDS_MSG_FIRST],
                         FALSE);
        }
        g_bConsoleRun = FALSE;
        SetCursor(g_hCursorArrow);
        return retValue;
    }
    return FALSE;
}


BOOL IsServiceRunning(LPCTSTR szServiceName, LPCTSTR szComputerName,
                      LPDWORD lpdwPid)
{
    DWORD dwPid;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;
    SERVICE_STATUS schSStatus;

    dwPid = 0;
    schSCManager = OpenSCManager(szComputerName, NULL,
                                SC_MANAGER_CONNECT);
    if (!schSCManager) {
        return FALSE;
    }

    schService = OpenService(schSCManager, szServiceName,
                             SERVICE_QUERY_STATUS);
    if (schService != NULL)
    {
        if (QueryServiceStatus(schService, &schSStatus))
        {
            dwPid = schSStatus.dwCurrentState;
            if (lpdwPid) {
                *lpdwPid = 1;
            }
        }
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return dwPid == SERVICE_RUNNING ? TRUE : FALSE;
    }
    else {
        g_bRescanServices = TRUE;
    }
    CloseServiceHandle(schSCManager);
    return FALSE;
}


BOOL FindRunningServices(void)
{
    int i = 0;
    DWORD dwPid;
    BOOL rv = FALSE;
    while (g_stServices[i].szServiceName != NULL)
    {
        if (!IsServiceRunning(g_stServices[i].szServiceName,
                              g_stServices[i].szComputerName, &dwPid)) {
            dwPid = 0;
        }
        if (g_stServices[i].dwPid != dwPid) {
            rv = TRUE;
        }
        g_stServices[i].dwPid = dwPid;
        ++i;
    }
    return rv;
}


BOOL GetApacheServicesStatus()
{
    TCHAR szKey[MAX_PATH];
    TCHAR achKey[MAX_PATH];
    TCHAR szImagePath[MAX_PATH];
    TCHAR szBuf[MAX_PATH];
    TCHAR szTmp[MAX_PATH];
    HKEY hKey, hSubKey, hKeyRemote;
    DWORD retCode, rv, dwKeyType;
    DWORD dwBufLen = MAX_PATH;
    int i, stPos = 0;
    int computers = 0;

    g_bRescanServices = FALSE;

    am_ClearServicesSt();
    while (g_stComputers[computers].szComputerName != NULL) {
        hKeyRemote = g_stComputers[computers].hRegistry;
        retCode = RegOpenKeyEx(hKeyRemote,
                               _T("System\\CurrentControlSet\\Services\\"),
                               0, KEY_READ, &hKey);
        if (retCode != ERROR_SUCCESS)
        {
            ErrorMessage(NULL, FALSE);
            return FALSE;
        }
        for (i = 0, retCode = ERROR_SUCCESS; retCode == ERROR_SUCCESS; i++)
        {
            retCode = RegEnumKey(hKey, i, achKey, MAX_PATH);
            if (retCode == ERROR_SUCCESS)
            {
                _tcscpy(szKey, _T("System\\CurrentControlSet\\Services\\"));
                _tcscat(szKey, achKey);

                if (RegOpenKeyEx(hKeyRemote, szKey, 0,
                                 KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
                {
                    dwBufLen = MAX_PATH;
                    rv = RegQueryValueEx(hSubKey, _T("ImagePath"), NULL,
                                         &dwKeyType, (LPBYTE)szImagePath, &dwBufLen);

                    if (rv == ERROR_SUCCESS
                            && (dwKeyType == REG_SZ
                             || dwKeyType == REG_EXPAND_SZ)
                            && dwBufLen)
                    {
                        _tcscpy(szBuf, szImagePath);
                        CharLower(szBuf);
                        /* the service name could be httpd*.exe or Apache*.exe */
                        if (((_tcsstr(szBuf, _T("\\apache")) != NULL)
                             || (_tcsstr(szBuf, _T("\\httpd")) != NULL))
                                && _tcsstr(szBuf, _T(".exe"))
                                && (_tcsstr(szBuf, _T("--ntservice")) != NULL
                                       || _tcsstr(szBuf, _T("-k ")) != NULL))
                        {
                            g_stServices[stPos].szServiceName = _tcsdup(achKey);
                            g_stServices[stPos].szImagePath = _tcsdup(szImagePath);
                            g_stServices[stPos].szComputerName =
                                _tcsdup(g_stComputers[computers].szComputerName);
                            dwBufLen = MAX_PATH;
                            if (RegQueryValueEx(hSubKey, _T("Description"), NULL,
                                                &dwKeyType, (LPBYTE)szBuf, &dwBufLen)
                                    == ERROR_SUCCESS) {
                                g_stServices[stPos].szDescription = _tcsdup(szBuf);
                            }
                            dwBufLen = MAX_PATH;
                            if (RegQueryValueEx(hSubKey, _T("DisplayName"), NULL,
                                                &dwKeyType, (LPBYTE)szBuf, &dwBufLen)
                                    == ERROR_SUCCESS)
                            {
                                if (_tcscmp(g_stComputers[computers]
                                        .szComputerName, g_szLocalHost) != 0)
                                {
                                    _tcscpy(szTmp, g_stComputers[computers]
                                                      .szComputerName + 2);
                                    _tcscat(szTmp, _T("@"));
                                    _tcscat(szTmp, szBuf);
                                }
                                else {
                                    _tcscpy(szTmp, szBuf);
                                }
                                g_stServices[stPos].szDisplayName = _tcsdup(szTmp);

                            }
                            ++stPos;
                            if (stPos >= MAX_APACHE_SERVICES) {
                                retCode = !ERROR_SUCCESS;
                            }
                        }
                    }
                    RegCloseKey(hSubKey);
                }
            }
        }
        ++computers;
        RegCloseKey(hKey);
    }
    FindRunningServices();
    return TRUE;
}


LRESULT CALLBACK ConnectDlgProc(HWND hDlg, UINT message,
                                WPARAM wParam, LPARAM lParam)
{
    TCHAR szCmp[MAX_COMPUTERNAME_LENGTH+4];
    switch (message)
    {
    case WM_INITDIALOG:
        ShowWindow(hDlg, SW_HIDE);
        g_hwndConnectDlg = hDlg;
        CenterWindow(hDlg);
        ShowWindow(hDlg, SW_SHOW);
        SetFocus(GetDlgItem(hDlg, IDC_COMPUTER));
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
            memset(szCmp, 0, sizeof(szCmp));
            _tcscpy(szCmp, _T("\\\\"));
            SendMessage(GetDlgItem(hDlg, IDC_COMPUTER), WM_GETTEXT,
                        (WPARAM) MAX_COMPUTERNAME_LENGTH,
                        (LPARAM) szCmp+2);

            _tcsupr(szCmp);
            if (_tcslen(szCmp) < 3) {
                EndDialog(hDlg, TRUE);
                return TRUE;
            }
            am_ConnectComputer(szCmp);
            SendMessage(g_hwndMain, WM_TIMER, WM_TIMER_RESCAN, 0);

        case IDCANCEL:
            EndDialog(hDlg, TRUE);
            return TRUE;

        case IDC_LBROWSE:
        {
            BROWSEINFO bi;
            ITEMIDLIST *il;
            LPMALLOC pMalloc;
            memset(&bi, 0, sizeof(BROWSEINFO));
            SHGetSpecialFolderLocation(hDlg, CSIDL_NETWORK, &il);

            bi.lpszTitle      = _T("ApacheMonitor :\nSelect Network Computer!");
            bi.pszDisplayName = szCmp;
            bi.hwndOwner =      hDlg;
            bi.ulFlags =        BIF_BROWSEFORCOMPUTER;
            bi.lpfn =           NULL;
            bi.lParam =         0;
            bi.iImage =         0;
            bi.pidlRoot =       il;

            if (SHBrowseForFolder(&bi) != NULL) {
                SendMessage(GetDlgItem(hDlg, IDC_COMPUTER),
                            WM_SETTEXT,
                            (WPARAM) NULL, (LPARAM) szCmp);
            }
            if (SHGetMalloc(&pMalloc)) {
                pMalloc->lpVtbl->Free(pMalloc, il);
                pMalloc->lpVtbl->Release(pMalloc);
            }
            return TRUE;
        }
        }
        break;

    case WM_QUIT:
    case WM_CLOSE:
        EndDialog(hDlg, TRUE);
        return TRUE;

    default:
        return FALSE;
    }
    return FALSE;

}


LRESULT CALLBACK ServiceDlgProc(HWND hDlg, UINT message,
                                WPARAM wParam, LPARAM lParam)
{
    TCHAR szBuf[MAX_PATH];
    HWND hListBox;
    static HWND hStatusBar;
    TEXTMETRIC tm;
    int i, y;
    HDC hdcMem;
    RECT rcBitmap;
    LRESULT nItem;
    LPMEASUREITEMSTRUCT lpmis;
    LPDRAWITEMSTRUCT lpdis;

    memset(szBuf, 0, sizeof(szBuf));
    switch (message)
    {
    case WM_INITDIALOG:
        ShowWindow(hDlg, SW_HIDE);
        g_hwndServiceDlg = hDlg;
        SetWindowText(hDlg, g_szTitle);
        Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SDISCONN), FALSE);
        SetWindowText(GetDlgItem(hDlg, IDC_SSTART),
                      g_lpMsg[IDS_MSG_SSTART - IDS_MSG_FIRST]);
        SetWindowText(GetDlgItem(hDlg, IDC_SSTOP),
                      g_lpMsg[IDS_MSG_SSTOP - IDS_MSG_FIRST]);
        SetWindowText(GetDlgItem(hDlg, IDC_SRESTART),
                      g_lpMsg[IDS_MSG_SRESTART - IDS_MSG_FIRST]);
        SetWindowText(GetDlgItem(hDlg, IDC_SMANAGER),
                      g_lpMsg[IDS_MSG_SERVICES - IDS_MSG_FIRST]);
        SetWindowText(GetDlgItem(hDlg, IDC_SCONNECT),
                      g_lpMsg[IDS_MSG_CONNECT - IDS_MSG_FIRST]);
        SetWindowText(GetDlgItem(hDlg, IDCANCEL),
                      g_lpMsg[IDS_MSG_OK - IDS_MSG_FIRST]);
        hListBox = GetDlgItem(hDlg, IDL_SERVICES);
        g_hwndStdoutList = GetDlgItem(hDlg, IDL_STDOUT);
        hStatusBar = CreateStatusWindow(0x0800 /* SBT_TOOLTIPS */
                                      | WS_CHILD | WS_VISIBLE,
                                        _T(""), hDlg, IDC_STATBAR);
        if (GetApacheServicesStatus())
        {
            i = 0;
            while (g_stServices[i].szServiceName != NULL)
            {
                addListBoxItem(hListBox, g_stServices[i].szDisplayName,
                               g_stServices[i].dwPid == 0 ? g_hBmpStop
                                                          : g_hBmpStart);
                ++i;
            }
        }
        CenterWindow(hDlg);
        ShowWindow(hDlg, SW_SHOW);
        SetFocus(hListBox);
        SendMessage(hListBox, LB_SETCURSEL, 0, 0);
        return TRUE;
        break;

    case WM_MANAGEMESSAGE:
        ApacheManageService(g_stServices[LOWORD(wParam)].szServiceName,
                    g_stServices[LOWORD(wParam)].szImagePath,
                    g_stServices[LOWORD(wParam)].szComputerName,
                    LOWORD(lParam));

        return TRUE;
        break;

    case WM_UPDATEMESSAGE:
        hListBox = GetDlgItem(hDlg, IDL_SERVICES);
        SendMessage(hListBox, LB_RESETCONTENT, 0, 0);
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)_T(""));
        Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
        Button_Enable(GetDlgItem(hDlg, IDC_SDISCONN), FALSE);
        i = 0;
        while (g_stServices[i].szServiceName != NULL)
        {
            addListBoxItem(hListBox, g_stServices[i].szDisplayName,
                g_stServices[i].dwPid == 0 ? g_hBmpStop : g_hBmpStart);
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
        lpmis->itemHeight = YBITMAP;
        return TRUE;

    case WM_SETCURSOR:
        if (g_bConsoleRun) {
            SetCursor(g_hCursorHourglass);
        }
        else {
            SetCursor(g_hCursorArrow);
        }
        return TRUE;

    case WM_DRAWITEM:
        lpdis = (LPDRAWITEMSTRUCT) lParam;
        if (lpdis->itemID == -1) {
            break;
        }
        switch (lpdis->itemAction)
        {
        case ODA_FOCUS:
        case ODA_SELECT:
        case ODA_DRAWENTIRE:
            g_hBmpPicture = (HBITMAP)SendMessage(lpdis->hwndItem,
                                                 LB_GETITEMDATA,
                                                 lpdis->itemID, (LPARAM) 0);

            hdcMem = CreateCompatibleDC(lpdis->hDC);
            g_hBmpOld = SelectObject(hdcMem, g_hBmpPicture);

            BitBlt(lpdis->hDC, lpdis->rcItem.left, lpdis->rcItem.top,
                   lpdis->rcItem.right - lpdis->rcItem.left,
                   lpdis->rcItem.bottom - lpdis->rcItem.top,
                   hdcMem, 0, 0, SRCCOPY);
            SendMessage(lpdis->hwndItem, LB_GETTEXT,
                        lpdis->itemID, (LPARAM) szBuf);

            GetTextMetrics(lpdis->hDC, &tm);
            y = (lpdis->rcItem.bottom + lpdis->rcItem.top - tm.tmHeight) / 2;

            SelectObject(hdcMem, g_hBmpOld);
            DeleteDC(hdcMem);

            rcBitmap.left = lpdis->rcItem.left + XBITMAP + 2;
            rcBitmap.top = lpdis->rcItem.top;
            rcBitmap.right = lpdis->rcItem.right;
            rcBitmap.bottom = lpdis->rcItem.top + YBITMAP;

            if (lpdis->itemState & ODS_SELECTED)
            {
                if (g_hBmpPicture == g_hBmpStop)
                {
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), TRUE);
                    Button_SetStyle(GetDlgItem(hDlg, IDC_SSTART), BS_DEFPUSHBUTTON, TRUE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                }
                else if (g_hBmpPicture == g_hBmpStart)
                {
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), TRUE);
                    Button_SetStyle(GetDlgItem(hDlg, IDC_SSTOP), BS_DEFPUSHBUTTON, TRUE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), TRUE);
                }
                else {
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                }
                if (_tcscmp(g_stServices[lpdis->itemID].szComputerName,
                           g_szLocalHost) == 0) {
                    Button_Enable(GetDlgItem(hDlg, IDC_SDISCONN), FALSE);
                }
                else {
                    Button_Enable(GetDlgItem(hDlg, IDC_SDISCONN), TRUE);
                }

                if (g_stServices[lpdis->itemID].szDescription) {
                    SendMessage(hStatusBar, SB_SETTEXT, 0,
                            (LPARAM)g_stServices[lpdis->itemID].szDescription);
                }
                else {
                    SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)_T(""));
                }
                if (lpdis->itemState & ODS_FOCUS) {
                    SetTextColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHTTEXT));
                    SetBkColor(lpdis->hDC, GetSysColor(COLOR_HIGHLIGHT));
                    FillRect(lpdis->hDC, &rcBitmap, (HBRUSH)(COLOR_HIGHLIGHT+1));
                }
                else {
                    SetTextColor(lpdis->hDC, GetSysColor(COLOR_INACTIVECAPTIONTEXT));
                    SetBkColor(lpdis->hDC, GetSysColor(COLOR_INACTIVECAPTION));
                    FillRect(lpdis->hDC, &rcBitmap, (HBRUSH)(COLOR_INACTIVECAPTION+1));
                }
            }
            else
            {
               SetTextColor(lpdis->hDC, GetSysColor(COLOR_MENUTEXT));
               SetBkColor(lpdis->hDC, GetSysColor(COLOR_WINDOW));
               FillRect(lpdis->hDC, &rcBitmap, (HBRUSH)(COLOR_WINDOW+1));
            }
            TextOut(lpdis->hDC, XBITMAP + 6, y, szBuf, (int)_tcslen(szBuf));
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
                /* if started then stop, if stopped then start */
                hListBox = GetDlgItem(hDlg, IDL_SERVICES);
                nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                if (nItem != LB_ERR)
                {
                    g_hBmpPicture = (HBITMAP)SendMessage(hListBox,
                                                         LB_GETITEMDATA,
                                                         nItem, (LPARAM) 0);
                    if (g_hBmpPicture == g_hBmpStop) {
                        SendMessage(hDlg, WM_MANAGEMESSAGE, nItem,
                                    SERVICE_CONTROL_CONTINUE);
                    }
                    else {
                        SendMessage(hDlg, WM_MANAGEMESSAGE, nItem,
                                    SERVICE_CONTROL_STOP);
                    }

                }
                return TRUE;
            }
            break;

        case IDCANCEL:
            EndDialog(hDlg, TRUE);
            return TRUE;

        case IDC_SSTART:
            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
            hListBox = GetDlgItem(hDlg, IDL_SERVICES);
            nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            if (nItem != LB_ERR) {
                SendMessage(hDlg, WM_MANAGEMESSAGE, nItem,
                            SERVICE_CONTROL_CONTINUE);
            }
            Button_Enable(GetDlgItem(hDlg, IDC_SSTART), TRUE);
            return TRUE;

        case IDC_SSTOP:
            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
            hListBox = GetDlgItem(hDlg, IDL_SERVICES);
            nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            if (nItem != LB_ERR) {
                SendMessage(hDlg, WM_MANAGEMESSAGE, nItem,
                            SERVICE_CONTROL_STOP);
            }
            Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), TRUE);
            return TRUE;

        case IDC_SRESTART:
            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
            hListBox = GetDlgItem(hDlg, IDL_SERVICES);
            nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            if (nItem != LB_ERR) {
                SendMessage(hDlg, WM_MANAGEMESSAGE, nItem,
                            SERVICE_APACHE_RESTART);
            }
            Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), TRUE);
            return TRUE;

        case IDC_SMANAGER:
            if (g_dwOSVersion >= OS_VERSION_WIN2K) {
                ShellExecute(hDlg, _T("open"), _T("services.msc"), _T("/s"),
                             NULL, SW_NORMAL);
            }
            else {
                WinExec("Control.exe SrvMgr.cpl Services", SW_NORMAL);
            }
            return TRUE;

        case IDC_SCONNECT:
            DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DLGCONNECT),
                      hDlg, (DLGPROC)ConnectDlgProc);
            return TRUE;

        case IDC_SDISCONN:
            hListBox = GetDlgItem(hDlg, IDL_SERVICES);
            nItem = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
            if (nItem != LB_ERR) {
                am_DisconnectComputer(g_stServices[nItem].szComputerName);
                SendMessage(g_hwndMain, WM_TIMER, WM_TIMER_RESCAN, 0);
            }
            return TRUE;
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

    case WM_QUIT:
    case WM_CLOSE:
        EndDialog(hDlg, TRUE);
        return TRUE;

    default:
        return FALSE;
    }
    return FALSE;
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message,
                          WPARAM wParam, LPARAM lParam)
{
    if (message == g_bUiTaskbarCreated)
    {
        /* restore the tray icon on shell restart */
        ShowNotifyIcon(hWnd, NIM_ADD);
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    switch (message)
    {
    case WM_CREATE:
        GetApacheServicesStatus();
        ShowNotifyIcon(hWnd, NIM_ADD);
        SetTimer(hWnd, WM_TIMER_REFRESH, REFRESH_TIME, NULL);
        SetTimer(hWnd, WM_TIMER_RESCAN,  RESCAN_TIME, NULL);
        break;

    case WM_TIMER:
        switch (wParam)
        {
        case WM_TIMER_RESCAN:
        {
            int nPrev = 0, nNew = 0;
            EnterCriticalSection(&g_stcSection);
            if (FindRunningServices() || g_bRescanServices)
            {
                ShowNotifyIcon(hWnd, NIM_MODIFY);
                if (g_hwndServiceDlg)
                    PostMessage(g_hwndServiceDlg, WM_UPDATEMESSAGE, 0, 0);
            }
            /* check if services list changed */
            while (g_stServices[nPrev].szServiceName != NULL)
                ++nPrev;
            GetApacheServicesStatus();
            while (g_stServices[nNew].szServiceName != NULL)
                ++nNew;
            if (nPrev != nNew)
            {
                ShowNotifyIcon(hWnd, NIM_MODIFY);
                if (g_hwndServiceDlg) {
                    PostMessage(g_hwndServiceDlg, WM_UPDATEMESSAGE, 0, 0);
                }
            }
            LeaveCriticalSection(&g_stcSection);
            break;
        }

        case WM_TIMER_REFRESH:
        {
            EnterCriticalSection(&g_stcSection);
            if (g_bRescanServices)
            {
                GetApacheServicesStatus();
                ShowNotifyIcon(hWnd, NIM_MODIFY);
                if (g_hwndServiceDlg) {
                    PostMessage(g_hwndServiceDlg, WM_UPDATEMESSAGE, 0, 0);
                }
            }
            else if (FindRunningServices())
            {
                ShowNotifyIcon(hWnd, NIM_MODIFY);
                if (g_hwndServiceDlg) {
                    PostMessage(g_hwndServiceDlg, WM_UPDATEMESSAGE, 0, 0);
                }
            }
            LeaveCriticalSection(&g_stcSection);
            break;
        }
        }
        break;

    case WM_QUIT:
        ShowNotifyIcon(hWnd, NIM_DELETE);
        break;

    case WM_TRAYMESSAGE:
        switch (lParam)
        {
        case WM_LBUTTONDBLCLK:
            if (!g_bDlgServiceOn)
            {
                g_bDlgServiceOn = TRUE;
                DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DLGSERVICES),
                          hWnd, (DLGPROC)ServiceDlgProc);
                g_bDlgServiceOn = FALSE;
                g_hwndServiceDlg = NULL;
            }
            else if (IsWindow(g_hwndServiceDlg))
            {
                /* Dirty hack to bring the window to the foreground */
                SetWindowPos(g_hwndServiceDlg, HWND_TOPMOST, 0, 0, 0, 0,
                             SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
                SetWindowPos(g_hwndServiceDlg, HWND_NOTOPMOST, 0, 0, 0, 0,
                             SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
                SetFocus(g_hwndServiceDlg);
            }
            break;

        case WM_LBUTTONUP:
            ShowTryServicesMenu(hWnd);
            break;

        case WM_RBUTTONUP:
            ShowTryPopupMenu(hWnd);
            break;
        }
        break;

    case WM_COMMAND:
        if ((LOWORD(wParam) & IDM_SM_START) == IDM_SM_START)
        {
            ApacheManageService(g_stServices[LOWORD(wParam)
                                           - IDM_SM_START].szServiceName,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_START].szImagePath,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_START].szComputerName,
                                SERVICE_CONTROL_CONTINUE);
            return TRUE;
        }
        else if ((LOWORD(wParam) & IDM_SM_STOP) == IDM_SM_STOP)
        {
            ApacheManageService(g_stServices[LOWORD(wParam)
                                           - IDM_SM_STOP].szServiceName,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_STOP].szImagePath,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_STOP].szComputerName,
                                SERVICE_CONTROL_STOP);
            return TRUE;
        }
        else if ((LOWORD(wParam) & IDM_SM_RESTART) == IDM_SM_RESTART)
        {
            ApacheManageService(g_stServices[LOWORD(wParam)
                                           - IDM_SM_RESTART].szServiceName,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_RESTART].szImagePath,
                                g_stServices[LOWORD(wParam)
                                           - IDM_SM_RESTART].szComputerName,
                                SERVICE_APACHE_RESTART);
            return TRUE;
        }
        switch (LOWORD(wParam))
        {
        case IDM_RESTORE:
            if (!g_bDlgServiceOn)
            {
                g_bDlgServiceOn = TRUE;
                DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DLGSERVICES),
                          hWnd, (DLGPROC)ServiceDlgProc);
                g_bDlgServiceOn = FALSE;
                g_hwndServiceDlg = NULL;
            }
            else if (IsWindow(g_hwndServiceDlg)) {
                SetFocus(g_hwndServiceDlg);
            }
            break;

        case IDC_SMANAGER:
            if (g_dwOSVersion >= OS_VERSION_WIN2K) {
                ShellExecute(NULL, _T("open"), _T("services.msc"), _T("/s"),
                             NULL, SW_NORMAL);
            }
            else {
                WinExec("Control.exe SrvMgr.cpl Services", SW_NORMAL);
            }
            return TRUE;

        case IDM_EXIT:
            ShowNotifyIcon(hWnd, NIM_DELETE);
            PostQuitMessage(0);
            return TRUE;
        }

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return FALSE;
}


static int KillAWindow(HWND appwindow)
{
    HANDLE appproc;
    DWORD procid;
    BOOL postres;

    SetLastError(0);
    GetWindowThreadProcessId(appwindow, &procid);
    if (GetLastError())
        return(2);

    appproc = OpenProcess(SYNCHRONIZE, 0, procid);
    postres = PostMessage(appwindow, WM_COMMAND, IDM_EXIT, 0);
    if (appproc && postres) {
        if (WaitForSingleObject(appproc, 10 /* seconds */ * 1000)
                == WAIT_OBJECT_0) {
            CloseHandle(appproc);
            return (0);
        }
    }
    if (appproc)
        CloseHandle(appproc);

    if ((appproc = OpenProcess(PROCESS_TERMINATE, 0, procid)) != NULL) {
        if (TerminateProcess(appproc, 0)) {
            CloseHandle(appproc);
            return (0);
        }
        CloseHandle(appproc);
    }

    /* Perhaps we were short of permissions? */
    return (2);
}


static int KillAllMonitors(void)
{
    HWND appwindow;
    int exitcode = 0;
    PWTS_PROCESS_INFO tsProcs;
    DWORD tsProcCount, i;
    DWORD thisProcId;

    /* This is graceful, close our own Window, clearing the icon */
    if ((appwindow = FindWindow(g_szWindowClass, g_szTitle)) != NULL)
        exitcode = KillAWindow(appwindow);

    if (g_dwOSVersion < OS_VERSION_WIN2K)
        return exitcode;

    thisProcId = GetCurrentProcessId();

    if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &tsProcs, &tsProcCount))
        return exitcode;

    /* This is ungraceful; close other Windows, with a lingering icon.
     * Since on terminal server it's not possible to post the message
     * to exit across sessions, we have to suffer this side effect
     * of a taskbar 'icon' which will evaporate the next time that
     * the user hovers over it or when the taskbar area is updated.
     */
    for (i = 0; i < tsProcCount; ++i) {
        if (_tcscmp(tsProcs[i].pProcessName, _T(AM_STRINGIFY(BIN_NAME))) == 0
                && tsProcs[i].ProcessId != thisProcId)
            WTSTerminateProcess(WTS_CURRENT_SERVER_HANDLE,
                                tsProcs[i].ProcessId, 1);
    }
    WTSFreeMemory(tsProcs);
    return exitcode;
}


/* Create main invisible window */
HWND CreateMainWindow(HINSTANCE hInstance)
{
    HWND hWnd = NULL;
    WNDCLASSEX wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = (WNDPROC)WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon   = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_APSRVMON),
                                    IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    wcex.hCursor        = g_hCursorArrow;
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = 0;
    wcex.lpszClassName  = g_szWindowClass;
    wcex.hIconSm = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_APSRVMON),
                                    IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    if (RegisterClassEx(&wcex)) {
        hWnd = CreateWindow(g_szWindowClass, g_szTitle,
                            0, 0, 0, 0, 0,
                            NULL, NULL, hInstance, NULL);
    }
    return hWnd;
}


#ifndef UNICODE
/* Borrowed from CRT internal.h for _MBCS argc/argv parsing in this GUI app */
int  __cdecl _setargv(void);
#endif

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    TCHAR szTmp[MAX_LOADSTRING];
    TCHAR szCmp[MAX_COMPUTERNAME_LENGTH+4];
    MSG msg;
    /* existing window */
    HWND appwindow;
    DWORD dwControl;
    int i;
    DWORD d;

    if (!GetSystemOSVersion(&g_dwOSVersion))
    {
        ErrorMessage(NULL, TRUE);
        return 1;
    }

    g_LangID = GetUserDefaultLangID();
    if ((g_LangID & 0xFF) != LANG_ENGLISH) {
        g_LangID = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
    }
    for (i = IDS_MSG_FIRST; i <= IDS_MSG_LAST; ++i) {
        LoadString(hInstance, i, szTmp, MAX_LOADSTRING);
        g_lpMsg[i - IDS_MSG_FIRST] = _tcsdup(szTmp);
    }
    LoadString(hInstance, IDS_APMONITORTITLE, szTmp, MAX_LOADSTRING);
    d = MAX_COMPUTERNAME_LENGTH+1;
    _tcscpy(szCmp, _T("\\\\"));
    GetComputerName(szCmp + 2, &d);
    _tcsupr(szCmp);
    g_szLocalHost = _tcsdup(szCmp);

    memset(g_stComputers, 0, sizeof(ST_MONITORED_COMP) * MAX_APACHE_COMPUTERS);
    g_stComputers[0].szComputerName = _tcsdup(szCmp);
    g_stComputers[0].hRegistry = HKEY_LOCAL_MACHINE;
    g_szTitle = _tcsdup(szTmp);
    LoadString(hInstance, IDS_APMONITORCLASS, szTmp, MAX_LOADSTRING);
    g_szWindowClass = _tcsdup(szTmp);

    appwindow = FindWindow(g_szWindowClass, g_szTitle);

#ifdef UNICODE
    __wargv = CommandLineToArgvW(GetCommandLineW(), &__argc);
#else
    _setargv();
#endif

    if ((__argc == 2) && (_tcscmp(__targv[1], _T("--kill")) == 0))
    {
        /* Off to chase and close up every ApacheMonitor taskbar window */
        return KillAllMonitors();
    }
    else if ((__argc == 4) && (g_dwOSVersion >= OS_VERSION_WIN2K))
    {
        dwControl = _ttoi(__targv[1]);
        if ((dwControl != SERVICE_CONTROL_CONTINUE) &&
            (dwControl != SERVICE_APACHE_RESTART) &&
            (dwControl != SERVICE_CONTROL_STOP))
        {
            return 1;
        }

        /* Chase down and close up our session's previous window */
        if ((appwindow) != NULL)
            KillAWindow(appwindow);
    }
    else if (__argc != 1) {
        return 1;
    }
    else if (appwindow)
    {
        ErrorMessage(g_lpMsg[IDS_MSG_APPRUNNING - IDS_MSG_FIRST], FALSE);
        return 0;
    }

    g_icoStop          = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICOSTOP),
                                   IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_icoRun           = LoadImage(hInstance, MAKEINTRESOURCE(IDI_ICORUN),
                                   IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    g_hCursorHourglass = LoadImage(NULL, MAKEINTRESOURCE(OCR_WAIT),
                                   IMAGE_CURSOR, LR_DEFAULTSIZE,
                                   LR_DEFAULTSIZE, LR_SHARED);
    g_hCursorArrow     = LoadImage(NULL, MAKEINTRESOURCE(OCR_NORMAL),
                                   IMAGE_CURSOR, LR_DEFAULTSIZE,
                                   LR_DEFAULTSIZE, LR_SHARED);
    g_hBmpStart        = LoadImage(hInstance, MAKEINTRESOURCE(IDB_BMPRUN),
                                   IMAGE_BITMAP, XBITMAP, YBITMAP,
                                   LR_DEFAULTCOLOR);
    g_hBmpStop         = LoadImage(hInstance, MAKEINTRESOURCE(IDB_BMPSTOP),
                                   IMAGE_BITMAP, XBITMAP, YBITMAP,
                                   LR_DEFAULTCOLOR);

    memset(g_stServices, 0, sizeof(ST_APACHE_SERVICE) * MAX_APACHE_SERVICES);
    CoInitialize(NULL);
    InitCommonControls();
    g_hInstance = hInstance;
    g_hwndMain = CreateMainWindow(hInstance);
    g_bUiTaskbarCreated = RegisterWindowMessage(_T("TaskbarCreated"));
    InitializeCriticalSection(&g_stcSection);
    g_hwndServiceDlg = NULL;
    if (g_hwndMain != NULL)
    {
        /* To avoid recursion, pass ImagePath NULL (a noop on NT and later) */
        if ((__argc == 4) && (g_dwOSVersion >= OS_VERSION_WIN2K))
            ApacheManageService(__targv[2], NULL, __targv[3], dwControl);

        while (GetMessage(&msg, NULL, 0, 0) == TRUE)
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        am_ClearServicesSt();
    }
    am_ClearComputersSt();
    DeleteCriticalSection(&g_stcSection);
    DestroyIcon(g_icoStop);
    DestroyIcon(g_icoRun);
    DestroyCursor(g_hCursorHourglass);
    DestroyCursor(g_hCursorArrow);
    DeleteObject(g_hBmpStart);
    DeleteObject(g_hBmpStop);
    CoUninitialize();
    return 0;
}

