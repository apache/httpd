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
#ifndef OEMRESOURCE
#define OEMRESOURCE
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdlib.h>
#include <stdio.h>
#include "ApacheMonitor.h"


#define OS_VERSION_WIN9X    1
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
    LPSTR    szServiceName;
    LPSTR    szDisplayName;
    LPSTR    szDescription;
    LPSTR    szImagePath;
    LPSTR    szComputerName;
    DWORD    dwPid;
} ST_APACHE_SERVICE;

typedef struct _st_MONITORED_COMPUTERS
{
    LPSTR   szComputerName;
    HKEY    hRegistry;
} ST_MONITORED_COMP;

/* Global variables */
HINSTANCE         g_hInstance = NULL;
CHAR             *g_szTitle;          /* The title bar text */
CHAR             *g_szWindowClass;    /* Window Class Name  */
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

HANDLE            g_hpipeOutRead;
HANDLE            g_hpipeOutWrite;
HANDLE            g_hpipeInRead;
HANDLE            g_hpipeInWrite;
HANDLE            g_hpipeStdError;
LANGID            g_LangID;
PROCESS_INFORMATION g_lpRedirectProc;
CRITICAL_SECTION  g_stcSection;
LPSTR             g_szLocalHost;

/* locale language support */
static CHAR *g_lpMsg[IDS_MSG_LAST - IDS_MSG_FIRST + 1];


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


BOOL am_IsComputerConnected(LPSTR szComputerName)
{
    int i = 0;
    while (g_stComputers[i].szComputerName != NULL) {
        if (strcmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            return TRUE;
        }
        ++i;
    }
    return FALSE;
}


void am_DisconnectComputer(LPSTR szComputerName)
{
    int i = 0, j;
    while (g_stComputers[i].szComputerName != NULL) {
        if (strcmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            break;
        }
        ++i;
    }
    if (g_stComputers[i].szComputerName != NULL) {
        free(g_stComputers[i].szComputerName);
        RegCloseKey(g_stComputers[i].hRegistry);
        for (j = i; j < MAX_APACHE_COMPUTERS - 1; j++) {
            g_stComputers[i].szComputerName= g_stComputers[i+1].szComputerName;
            g_stComputers[i].hRegistry = g_stComputers[i+1].hRegistry;
        }
        for (i = j; i < MAX_APACHE_COMPUTERS; i++) {
            g_stComputers[i].szComputerName = NULL;
            g_stComputers[i].hRegistry = NULL;
        }
    } 

}


void ErrorMessage(LPCSTR szError, BOOL bFatal)
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
                      (LPSTR) &lpMsgBuf, 0, NULL);
        MessageBox(NULL, (LPCSTR)lpMsgBuf, 
                   g_lpMsg[IDS_MSG_ERROR - IDS_MSG_FIRST],
                   MB_OK | (bFatal ? MB_ICONERROR : MB_ICONEXCLAMATION));
        LocalFree(lpMsgBuf);
    }
    if (bFatal) {
        PostQuitMessage(0);
    }
}


BOOL am_ConnectComputer(LPSTR szComputerName)
{
    int i = 0;
    HKEY hKeyRemote;
    char szTmp[MAX_PATH];

    while (g_stComputers[i].szComputerName != NULL) {
        if (strcmp(g_stComputers[i].szComputerName, szComputerName) == 0) {
            return FALSE;
        }
        ++i;
    }
    if (i > MAX_APACHE_COMPUTERS - 1) {
        return FALSE;
    }
    if (RegConnectRegistry(szComputerName, HKEY_LOCAL_MACHINE, &hKeyRemote) 
            != ERROR_SUCCESS) {
        sprintf(szTmp, g_lpMsg[IDS_MSG_ECONNECT - IDS_MSG_FIRST], 
                szComputerName);
        ErrorMessage(szTmp, FALSE);
        return FALSE;
    }
    else {
        g_stComputers[i].szComputerName = strdup(szComputerName);
        g_stComputers[i].hRegistry = hKeyRemote;
        return TRUE;
    }
} 


LPSTR GetStringRes(int id)
{
    static CHAR buffer[MAX_PATH];

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
        if (osvi.dwMajorVersion <= 4) {
            *dwVersion = OS_VERSION_WINNT;
        }
        else if (osvi.dwMajorVersion == 5) {
            *dwVersion = OS_VERSION_WIN2K;
        }
        else {
            return FALSE;
        }
        break;

    case VER_PLATFORM_WIN32_WINDOWS:
        *dwVersion = OS_VERSION_WIN9X;
        break;

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
        lstrcpy(nid.szTip, g_lpMsg[IDS_MSG_RUNNINGALL - IDS_MSG_FIRST]);
    }
    else if (n) {
        sprintf(nid.szTip, g_lpMsg[IDS_MSG_RUNNING - IDS_MSG_FIRST], n, i);
    }
    else if (i) {
        sprintf(nid.szTip, g_lpMsg[IDS_MSG_RUNNINGNONE - IDS_MSG_FIRST], i);
    }
    else {
        lstrcpy(nid.szTip, g_lpMsg[IDS_MSG_NOSERVICES - IDS_MSG_FIRST]);
    }
    Shell_NotifyIcon(dwMessage, &nid);
}


void appendMenuItem(HMENU hMenu, UINT uMenuId, LPSTR szName, 
                    BOOL fDefault, BOOL fEnabled)
{
    MENUITEMINFO mii;

    memset(&mii, 0, sizeof(MENUITEMINFO));
    mii.cbSize = sizeof(MENUITEMINFO);
    mii.fMask = MIIM_ID | MIIM_TYPE | MIIM_STATE;
    if (lstrlen(szName))
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
                       LPSTR szServiceName, BOOL fRunning)
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
        if (g_dwOSVersion >= OS_VERSION_WINNT) {
            appendMenuItem(hMenu, IDC_SMANAGER, 
                           g_lpMsg[IDS_MSG_MNUSERVICES - IDS_MSG_FIRST], 
                           FALSE, TRUE);
        }
        appendMenuItem(hMenu, 0, "", FALSE, TRUE);
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


static void addListBoxItem(HWND hDlg, LPSTR lpStr, HBITMAP hBmp) 
{ 
    int nItem; 
 
    nItem = SendMessage(hDlg, LB_ADDSTRING, 0, (LPARAM)lpStr); 
    SendMessage(hDlg, LB_SETITEMDATA, nItem, (LPARAM)hBmp); 
} 


static void addListBoxString(HWND hListBox, LPSTR lpStr)
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


static DWORD WINAPI ConsoleOutputThread(LPVOID lpThreadParameter)
{
    static BYTE lpBuffer[MAX_PATH+1];
    int nPtr = 0;
    BYTE ch;
    DWORD dwReaded;

    while (ReadFile(g_hpipeOutRead, &ch, 1, &dwReaded, NULL) == TRUE) 
    {
        if (dwReaded > 0) 
        {
            if (ch == '\n' || nPtr >= MAX_PATH) 
            {
                lpBuffer[nPtr] = '\0';
                addListBoxString(g_hwndStdoutList, lpBuffer);
                nPtr = 0;
            } 
            else if (ch == '\t' && nPtr < (MAX_PATH - 4)) 
            {
                int i;
                for (i = 0; i < 4; ++i) {
                    lpBuffer[nPtr++] = ' ';
                }
            }
            else if (ch != '\r') {
                lpBuffer[nPtr++] = ch;
            }
        }
    }
    CloseHandle(g_hpipeInWrite);
    CloseHandle(g_hpipeOutRead);
    CloseHandle(g_hpipeStdError);
    return 0;
}


DWORD WINAPI ConsoleWaitingThread(LPVOID lpThreadParameter)
{
    WaitForSingleObject(g_lpRedirectProc.hThread, INFINITE);
    CloseHandle(g_lpRedirectProc.hThread);
    MessageBeep(100);
    g_bConsoleRun = FALSE;
    SetCursor(g_hCursorArrow);
    return 0;
}


BOOL RunRedirectedConsole(LPSTR szCmdLine)
{
    DWORD dwThreadId;
    HANDLE hProc;
    STARTUPINFO stInfo;
    BOOL bResult;

    memset(&stInfo, 0, sizeof(stInfo));
    stInfo.cb = sizeof(stInfo);
    stInfo.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    stInfo.wShowWindow = SW_HIDE;

    hProc = GetCurrentProcess();

    if (!CreatePipe(&g_hpipeInRead, &g_hpipeInWrite, NULL, MAX_PATH)) {
        ErrorMessage(NULL, TRUE);
    }
    if (!CreatePipe(&g_hpipeOutRead, &g_hpipeOutWrite, NULL, MAX_PATH*8)) {
        ErrorMessage(NULL, TRUE);
    }
    DuplicateHandle(hProc, g_hpipeInRead, hProc, &g_hpipeInRead, 0, TRUE, 
                    DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS);
    DuplicateHandle(hProc, g_hpipeOutWrite, hProc, &g_hpipeOutWrite, 0, TRUE, 
                    DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS);
    DuplicateHandle(hProc, g_hpipeOutWrite, hProc, &g_hpipeStdError, 0, TRUE, 
                    DUPLICATE_SAME_ACCESS);
    if (!g_hpipeInRead && !g_hpipeOutWrite && !g_hpipeStdError) {
        ErrorMessage(NULL, TRUE);
    }
    stInfo.hStdInput  = g_hpipeInRead;
    stInfo.hStdOutput = g_hpipeOutWrite;
    stInfo.hStdError  = g_hpipeStdError;

    bResult = CreateProcess(NULL,
        szCmdLine,
        NULL,
        NULL,
        TRUE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &stInfo,
        &g_lpRedirectProc);


    CloseHandle(g_hpipeInRead);
    CloseHandle(g_hpipeOutWrite);
    CloseHandle(g_hpipeStdError);

    if (!bResult)
    {
        CloseHandle(g_hpipeInWrite);
        CloseHandle(g_hpipeOutRead);
        CloseHandle(g_hpipeStdError);
        return FALSE;
    }

    CloseHandle(CreateThread(NULL, 0, ConsoleOutputThread, 
                             0, 0, &dwThreadId));
    ResumeThread(g_lpRedirectProc.hThread);
    CloseHandle(CreateThread(NULL, 0, ConsoleWaitingThread,
                             0, 0, &dwThreadId));

    return TRUE;
}


BOOL RunAndForgetConsole(LPSTR szCmdLine, BOOL bRedirectConsole)
{
    STARTUPINFO stInfo;
    PROCESS_INFORMATION prInfo;
    BOOL bResult;

    if (bRedirectConsole) {
        return RunRedirectedConsole(szCmdLine);
    }

    memset(&stInfo, 0, sizeof(stInfo));
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
                            NULL,
                            &stInfo,
                            &prInfo);

    if (!bResult) {
        return FALSE;
    }
    if (g_dwOSVersion == OS_VERSION_WIN9X) {
        /* give some time to rescan the status */
        Sleep(2000);
    }
    CloseHandle(prInfo.hThread);
    CloseHandle(prInfo.hProcess);
    return TRUE;
}


BOOL ApacheManageService(LPCSTR szServiceName, LPCSTR szImagePath, 
                         LPSTR szComputerName, DWORD dwCommand)
{
    CHAR szBuf[MAX_PATH];
    CHAR szMsg[MAX_PATH];
    LPSTR sPos;
    BOOL retValue;
    BOOL serviceFlag = TRUE;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;
    SERVICE_STATUS schSStatus;
    int ticks;

    if (g_dwOSVersion == OS_VERSION_WIN9X)
    {
        sPos = strstr(szImagePath, "-k start");
        if (sPos)
        {
            lstrcpyn(szBuf, szImagePath, sPos - szImagePath);
            switch (dwCommand)
            {
            case SERVICE_CONTROL_STOP:
                lstrcat(szBuf, " -k shutdown -n ");
                break;

            case SERVICE_CONTROL_CONTINUE:
                sprintf(szMsg, g_lpMsg[IDS_MSG_SRVSTART - IDS_MSG_FIRST], 
                        szServiceName);
                addListBoxString(g_hwndStdoutList, szMsg);
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
        else {
            return FALSE;
        }
        g_bConsoleRun = TRUE;
        SetCursor(g_hCursorHourglass);
        if (!RunAndForgetConsole(szBuf, serviceFlag))
        {
            ErrorMessage(NULL, FALSE);
            g_bConsoleRun = FALSE;
            SetCursor(g_hCursorArrow);
            return FALSE;
        }
        else if (!serviceFlag)
        {
            sprintf(szMsg, g_lpMsg[IDS_MSG_SRVSTARTED - IDS_MSG_FIRST], 
                    szServiceName);
            addListBoxString(g_hwndStdoutList, szMsg);
            g_bConsoleRun = FALSE;
            SetCursor(g_hCursorArrow);
            return TRUE;
        }
    }
    else
    {
        schSCManager = OpenSCManager(szComputerName, NULL,
                                     SC_MANAGER_CONNECT);
        if (!schSCManager) {
            return FALSE;
        }

        schService = OpenService(schSCManager, szServiceName, 
                                 SERVICE_QUERY_STATUS | SERVICE_START | 
                                 SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL);
        if (schService != NULL)
        {
            retValue = FALSE;
            g_bConsoleRun = TRUE;
            SetCursor(g_hCursorHourglass);
            switch (dwCommand)
            {
            case SERVICE_CONTROL_STOP:
                sprintf(szMsg, g_lpMsg[IDS_MSG_SRVSTOP - IDS_MSG_FIRST], 
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
                        sprintf(szMsg, 
                                g_lpMsg[IDS_MSG_SRVSTOPPED - IDS_MSG_FIRST], 
                                szServiceName);
                        addListBoxString(g_hwndStdoutList, szMsg);
                    }
                }
                break;

            case SERVICE_CONTROL_CONTINUE:
                sprintf(szMsg, g_lpMsg[IDS_MSG_SRVSTART - IDS_MSG_FIRST],
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
                        sprintf(szMsg, 
                                g_lpMsg[IDS_MSG_SRVSTARTED - IDS_MSG_FIRST],
                                szServiceName);
                        addListBoxString(g_hwndStdoutList, szMsg);
                    }
                }
                break;

            case SERVICE_APACHE_RESTART:
                sprintf(szMsg, g_lpMsg[IDS_MSG_SRVRESTART - IDS_MSG_FIRST],
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
                    sprintf(szMsg, 
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
        else {
            g_bRescanServices = TRUE;
        }
        CloseServiceHandle(schSCManager);
        return FALSE;
    }

    return FALSE;
}


BOOL IsServiceRunning(LPCSTR szServiceName, LPCSTR szComputerName, 
                      LPDWORD lpdwPid)
{
    DWORD dwPid;
    HWND hWnd;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;
    SERVICE_STATUS schSStatus;

    if (g_dwOSVersion == OS_VERSION_WIN9X)
    {
        hWnd = FindWindow("ApacheWin95ServiceMonitor", szServiceName);
        if (hWnd && GetWindowThreadProcessId(hWnd, &dwPid)) 
        {
            *lpdwPid = 1;
            return TRUE;
        }
        else {
            return FALSE;
        }
    }
    else
    {
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
    CHAR szKey[MAX_PATH];
    CHAR achKey[MAX_PATH];
    CHAR szImagePath[MAX_PATH];
    CHAR szBuf[MAX_PATH];
    CHAR szTmp[MAX_PATH];
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
                               "System\\CurrentControlSet\\Services\\",
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
                lstrcpy(szKey, "System\\CurrentControlSet\\Services\\");
                lstrcat(szKey, achKey);

                if (RegOpenKeyEx(hKeyRemote, szKey, 0, 
                                 KEY_QUERY_VALUE, &hSubKey) == ERROR_SUCCESS)
                {
                    dwBufLen = MAX_PATH;
                    rv = RegQueryValueEx(hSubKey, "ImagePath", NULL,
                                         &dwKeyType, szImagePath, &dwBufLen);

                    if (rv == ERROR_SUCCESS
                            && (dwKeyType == REG_SZ 
                             || dwKeyType == REG_EXPAND_SZ)
                            && dwBufLen)
                    {
                        lstrcpy(szBuf, szImagePath);
                        CharLower(szBuf);
                        /* the service name could be Apache*.exe */
                        if ((strstr(szBuf, "\\apache") != NULL)
                                && strstr(szBuf, ".exe") 
                                && (strstr(szBuf, "--ntservice") != NULL 
                                       || strstr(szBuf, "-k ") != NULL))
                        {
                            g_stServices[stPos].szServiceName = strdup(achKey);
                            g_stServices[stPos].szImagePath = 
                                                           strdup(szImagePath);
                            g_stServices[stPos].szComputerName = 
                               strdup(g_stComputers[computers].szComputerName);
                            dwBufLen = MAX_PATH;
                            if (RegQueryValueEx(hSubKey, "Description", NULL,
                                                &dwKeyType, szBuf, &dwBufLen) 
                                    == ERROR_SUCCESS) {
                                g_stServices[stPos].szDescription = 
                                                                 strdup(szBuf);
                            }
                            dwBufLen = MAX_PATH;
                            if (RegQueryValueEx(hSubKey, "DisplayName", NULL,
                                                &dwKeyType, szBuf, &dwBufLen) 
                                    == ERROR_SUCCESS) 
                            {
                                if (strcmp(g_stComputers[computers]
                                        .szComputerName, g_szLocalHost) != 0) 
                                { 
                                    strcpy(szTmp, g_stComputers[computers]
                                                      .szComputerName + 2);
                                    strcat(szTmp, "@");
                                    strcat(szTmp, szBuf);
                                }
                                else {
                                    strcpy(szTmp, szBuf);
                                }
                                g_stServices[stPos].szDisplayName 
                                                        = strdup(szTmp);

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
    }
    RegCloseKey(hKey);
    FindRunningServices();
    return TRUE;
}


LRESULT CALLBACK ConnectDlgProc(HWND hDlg, UINT message, 
                                WPARAM wParam, LPARAM lParam)
{
    CHAR szCmp[MAX_COMPUTERNAME_LENGTH+4];
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
            memset(szCmp, 0, MAX_COMPUTERNAME_LENGTH+4);
            strcpy(szCmp, "\\\\");
            SendMessage(GetDlgItem(hDlg, IDC_COMPUTER), WM_GETTEXT, 
                        (WPARAM) MAX_COMPUTERNAME_LENGTH, 
                        (LPARAM) szCmp+2); 

            strupr(szCmp);
            if (strlen(szCmp) < 3) {
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

            bi.lpszTitle      = "ApacheMonitor :\nSelect Network Computer!";
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
    CHAR szBuf[MAX_PATH]; 
    HWND hListBox;
    static HWND hStatusBar; 
    TEXTMETRIC tm; 
    int i, y; 
    HDC hdcMem; 
    RECT rcBitmap; 
    UINT nItem;
    LPMEASUREITEMSTRUCT lpmis; 
    LPDRAWITEMSTRUCT lpdis; 

    memset(szBuf, 0, MAX_PATH);
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
        SetWindowText(GetDlgItem(hDlg, IDC_SEXIT), 
                      g_lpMsg[IDS_MSG_MNUEXIT - IDS_MSG_FIRST]);
        if (g_dwOSVersion < OS_VERSION_WINNT)
        {
            ShowWindow(GetDlgItem(hDlg, IDC_SMANAGER), SW_HIDE);
            ShowWindow(GetDlgItem(hDlg, IDC_SCONNECT), SW_HIDE);
            ShowWindow(GetDlgItem(hDlg, IDC_SDISCONN), SW_HIDE);
        }
        hListBox = GetDlgItem(hDlg, IDL_SERVICES); 
        g_hwndStdoutList = GetDlgItem(hDlg, IDL_STDOUT);
        hStatusBar = CreateStatusWindow(0x0800 /* SBT_TOOLTIPS */
                                      | WS_CHILD | WS_VISIBLE,
                                        "", hDlg, IDC_STATBAR);
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
        SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)"");
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
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                }
                else if (g_hBmpPicture == g_hBmpStart) 
                {
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), TRUE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), TRUE);
                }
                else {
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTART), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SSTOP), FALSE);
                    Button_Enable(GetDlgItem(hDlg, IDC_SRESTART), FALSE);
                }
                if (strcmp(g_stServices[lpdis->itemID].szComputerName, 
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
                    SendMessage(hStatusBar, SB_SETTEXT, 0, (LPARAM)"");
                }
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
            TextOut(lpdis->hDC, XBITMAP + 6, y, szBuf, strlen(szBuf)); 
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

        case IDOK: 
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
                ShellExecute(hDlg, "open", "services.msc", "/s",
                             NULL, SW_NORMAL);
            }
            else {
                WinExec("Control.exe SrvMgr.cpl Services", SW_NORMAL);
            }
            return TRUE;

        case IDC_SEXIT: 
            EndDialog(hDlg, TRUE);
            SendMessage(g_hwndMain, WM_COMMAND, (WPARAM)IDM_EXIT, 0);
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
            int nPrev = 0, nNew = 0;
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
                ShellExecute(NULL, "open", "services.msc", "/s",
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


/* Create main invisible window */
HWND CreateMainWindow(HINSTANCE hInstance)
{
    HWND hWnd = NULL;
    WNDCLASSEX wcex;

    if (!GetSystemOSVersion(&g_dwOSVersion))
    {
        ErrorMessage(NULL, TRUE);
        return hWnd;
    }

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


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    CHAR szTmp[MAX_LOADSTRING];
    CHAR szCmp[MAX_COMPUTERNAME_LENGTH+4];
    MSG msg;
    /* single instance mutex */
    HANDLE hMutex;
    int i;
    DWORD d;

    g_LangID = GetUserDefaultLangID();
    if ((g_LangID & 0xFF) != LANG_ENGLISH) {
        g_LangID = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
    }
    for (i = IDS_MSG_FIRST; i <= IDS_MSG_LAST; ++i) {
        LoadString(hInstance, i, szTmp, MAX_LOADSTRING);
        g_lpMsg[i - IDS_MSG_FIRST] = strdup(szTmp);
    }
    LoadString(hInstance, IDS_APMONITORTITLE, szTmp, MAX_LOADSTRING);
    d = MAX_COMPUTERNAME_LENGTH+1;
    strcpy(szCmp, "\\\\");
    GetComputerName(szCmp + 2, &d);
    strupr(szCmp);
    g_szLocalHost = strdup(szCmp);

    memset(g_stComputers, 0, sizeof(ST_MONITORED_COMP) * MAX_APACHE_COMPUTERS);
    g_stComputers[0].szComputerName = strdup(szCmp);
    g_stComputers[0].hRegistry = HKEY_LOCAL_MACHINE;
    g_szTitle = strdup(szTmp);
    LoadString(hInstance, IDS_APMONITORCLASS, szTmp, MAX_LOADSTRING);
    g_szWindowClass = strdup(szTmp);

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

    hMutex = CreateMutex(NULL, FALSE, "APSRVMON_MUTEX");
    if ((hMutex == NULL) || (GetLastError() == ERROR_ALREADY_EXISTS))
    {
        ErrorMessage(g_lpMsg[IDS_MSG_APPRUNNING - IDS_MSG_FIRST], FALSE);
        if (hMutex) {
            CloseHandle(hMutex);
        }
        return 0;
    }

    memset(g_stServices, 0, sizeof(ST_APACHE_SERVICE) * MAX_APACHE_SERVICES);
    CoInitialize(NULL);
    InitCommonControls();
    g_hInstance = hInstance;
    g_hwndMain = CreateMainWindow(hInstance);
    g_bUiTaskbarCreated = RegisterWindowMessage("TaskbarCreated");
    InitializeCriticalSection(&g_stcSection);
    g_hwndServiceDlg = NULL;
    if (g_hwndMain != NULL)
    {
        while (GetMessage(&msg, NULL, 0, 0) == TRUE) 
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        am_ClearServicesSt();
    }
    am_ClearComputersSt();
    DeleteCriticalSection(&g_stcSection);
    CloseHandle(hMutex);
    DestroyIcon(g_icoStop);
    DestroyIcon(g_icoRun);
    DestroyCursor(g_hCursorHourglass);
    DestroyCursor(g_hCursorArrow);
    DeleteObject(g_hBmpStart); 
    DeleteObject(g_hBmpStop); 
    CoUninitialize();
    return 0;
}
