/* ====================================================================
 * Copyright (c) 1995-2000 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://httpd.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://httpd.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/*
 * Win9xConHook.dll - a hook proc to clean up Win95/98 console behavior.
 *
 * It is well(?) documented by Microsoft that the Win9x HandlerRoutine
 * hooked by the SetConsoleCtrlHandler never receives the CTRL_CLOSE_EVENT,
 * CTRL_LOGOFF_EVENT or CTRL_SHUTDOWN_EVENT signals.  
 *
 * It is possible to have a second window to monitor the WM_ENDSESSION 
 * message, but the close button still fails..
 * 
 * There is a 16bit polling method for the close window option, but this
 * is CPU intensive and requires thunking.
 *
 * Attempts to subclass the 'tty' console fail, since that message thread
 * is actually owned by the 16 bit winoldap.mod process, although the 
 * window reports it is owned by the process/thread of the console app.
 *
 * Win9xConHook is thunks the WM_CLOSE and WM_ENDSESSION messages,
 * first through a window hook procedure in the winoldap context, into
 * a subclass WndProc, and on to a second hidden monitor window in the
 * console application's context that dispatches them to the console app's
 * registered HandlerRoutine.
 */

#define DBG 1

#include <windows.h>

/*
 *  is_tty flags this process;  -1 == unknown, 1 == if tty, 0 == if not
 *  hw_tty is the handle of the top level tty in this process context
 *  is_subclassed is toggled to assure DllMain removes the subclass
 *  is_hooked is toggled to assure DllMain removes the subclass
 */
static int is_tty = -1;
static HWND hwtty = NULL;
static BOOL is_subclassed = 0;

static HMODULE hmodHook = NULL;
static HHOOK hhkGetMessage;
//static HHOOK hhkCallWndProc;

static LPCTSTR origwndprop = NULL;
static LPCTSTR hookwndprop = NULL;

#ifdef DBG
static VOID DbgPrintf(LPTSTR fmt, ...);
#endif

static BOOL CALLBACK EnumttyWindow(HWND wnd, LPARAM retwnd);


BOOL __declspec(dllexport) APIENTRY DllMain(PVOID hModule, ULONG ulReason, PCONTEXT pctx)
{
    if (ulReason == DLL_PROCESS_ATTACH) 
    {
#ifdef DBG
        DbgPrintf("H ProcessAttach:%8.8x\r\n", GetCurrentProcessId());
#endif
        origwndprop = MAKEINTATOM(GlobalAddAtom("Win9xConHookOrigProc"));
        hookwndprop = MAKEINTATOM(GlobalAddAtom("Win9xConHookThunkWnd"));
    }
    else if ( ulReason == DLL_PROCESS_DETACH ) 
    {
        HWND parent;
#ifdef DBG
        DbgPrintf("H ProcessDetach:%8.8x\r\n", GetCurrentProcessId());                
#endif
        if (is_subclassed) {
            WNDPROC origproc = (WNDPROC) GetProp(hwtty, origwndprop);
            if (origproc) {
                SetWindowLong(hwtty, GWL_WNDPROC, (LONG)origproc);
                RemoveProp(hwtty, origwndprop);
            }
        }
        EnumWindows(EnumttyWindow, (LPARAM)&parent);
        if (parent) {
            HWND child = (HWND)GetProp(parent, hookwndprop);
            if (child)
                SendMessage(child, WM_DESTROY, 0, 0);
        }
        if (hmodHook)
        {
            if (hhkGetMessage) {
                UnhookWindowsHookEx(hhkGetMessage);
                hhkGetMessage = NULL;
            }
            FreeLibrary(hmodHook);
            hmodHook = NULL;
        }
        GlobalDeleteAtom((ATOM)origwndprop);
        GlobalDeleteAtom((ATOM)hookwndprop);
    }
    return TRUE;
}


typedef struct {
    PHANDLER_ROUTINE phandler;
    HINSTANCE instance;
    HWND parent;
} tty_info;


#define gwltty_phandler 0
#define gwltty_ttywnd 4

/* This is the WndProc procedure for our invisible window.
 * When our tty subclass WndProc recieves the WM_CLOSE, 
 * or WM_QUERYENDSESSION messages, we call the installed
 * HandlerRoutine that was registered with 
 * If a user logs off, the window is sent WM_QUERYENDSESSION 
 * as well, but with lParam != 0. We ignore this case.
 */
LRESULT CALLBACK ttyConsoleCtrlWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CREATE)
    {
        tty_info *tty = (tty_info*)(((LPCREATESTRUCT)lParam)->lpCreateParams);
        SetWindowLong(hwnd, gwltty_phandler, (LONG)tty->phandler);
        SetWindowLong(hwnd, gwltty_ttywnd, (LONG)tty->parent);
#ifdef DBG
        DbgPrintf("S Created ttyConHookChild:%8.8x\r\n", hwnd);
#endif
        SetProp(((tty_info*)tty)->parent, hookwndprop, hwnd);
        return 0;
    }
    else if (msg == WM_DESTROY)
    {
        HWND parent = (HWND)GetWindowLong(hwnd, gwltty_ttywnd);
        RemoveProp(parent, hookwndprop);
    }
    else if (msg == WM_CLOSE)
    {
        PHANDLER_ROUTINE phandler = 
            (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
#ifdef DBG
        DbgPrintf("S Invoking CTRL_CLOSE_EVENT:%8.8x\r\n",
                  GetCurrentProcessId());
#endif
        return !phandler(CTRL_CLOSE_EVENT);
    }
    else if (msg == WM_QUERYENDSESSION)
    {
        if (lParam & ENDSESSION_LOGOFF) 
        {
            PHANDLER_ROUTINE phandler = 
                (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
#ifdef DBG
            DbgPrintf("S Invoking CTRL_LOGOFF_EVENT:%8.8x\r\n",
                      GetCurrentProcessId());
#endif
            return !phandler(CTRL_LOGOFF_EVENT);
        }
        else
        {
            PHANDLER_ROUTINE phandler = 
                (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
#ifdef DBG
            DbgPrintf("S Invoking CTRL_SHUTDOWN_EVENT:%8.8x\r\n",
                      GetCurrentProcessId());
#endif
            return !phandler(CTRL_SHUTDOWN_EVENT);
        }
    }
    return (DefWindowProc(hwnd, msg, wParam, lParam));
}


DWORD WINAPI ttyConsoleCtrlThread(LPVOID tty)
{
    /* When running as a service under Windows 9x, ConsoleCtrlHandler 
     * does not respond properly when the user logs off or the system 
     * is shutdown.  If the WatchWindow thread is created with a NULL
     * service_name argument, then the ...SystemMonitor window class is
     * used to create the "Apache" window to watch for logoff and shutdown.
     * If the service_name is provided, the ...ServiceMonitor window class
     * is used to create the window named by the service_name argument,
     * and the logoff message is ignored.
     */
    WNDCLASS wc;
    HWND hwnd;
    MSG msg;
    wc.style         = CS_GLOBALCLASS;
    wc.lpfnWndProc   = ttyConsoleCtrlWndProc; 
    wc.cbClsExtra    = 0;
    wc.cbWndExtra    = 8; 
    wc.hInstance     = NULL;
    wc.hIcon         = NULL;
    wc.hCursor       = NULL;
    wc.hbrBackground = NULL;
    wc.lpszMenuName  = NULL;
    wc.lpszClassName = "ttyConHookChild";
    
    if (!RegisterClass(&wc)) { 
#ifdef DBG
        DbgPrintf("S Created ttyConHookChild class\r\n");
#endif
        return 0;
    }

    /* Create an invisible window */
    hwnd = CreateWindow(wc.lpszClassName, "", 
                        WS_OVERLAPPED & ~WS_VISIBLE,
                        CW_USEDEFAULT, CW_USEDEFAULT, 
                        CW_USEDEFAULT, CW_USEDEFAULT, 
                        NULL, NULL, 
                        ((tty_info*)tty)->instance, tty);

    if (!hwnd) {
#ifdef DBG
        DbgPrintf("S Error Creating ttyConHookChild:%d\r\n", GetLastError());
#endif
        return 0;
    }

    while (GetMessage(&msg, NULL, 0, 0)) 
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        if (msg.message == WM_DESTROY)
            DestroyWindow(hwnd);
    }
    return 0;
}


/* 
 * This function only works when this process is the active process 
 * (e.g. once it is running a child process, it can no longer determine 
 * which console window is its own.)
 */
static BOOL CALLBACK EnumttyWindow(HWND wnd, LPARAM retwnd)
{
    char tmp[4];
    if (GetClassName(wnd, tmp, sizeof(tmp)) && !strcmp(tmp, "tty")) 
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


/*
 * Exported function that sets up the fixup child window and dispatch
 */
BOOL __declspec(dllexport) WINAPI FixConsoleCtrlHandler(
        PHANDLER_ROUTINE phandler,
        BOOL add)
{
    HWND parent;
    EnumWindows(EnumttyWindow, (LPARAM)&parent);

    if (!parent)
        return FALSE;

    if (add)
    {
        HANDLE hThread;
        DWORD tid;
        static tty_info tty;
        tty.phandler = phandler;
        tty.parent = parent;
        tty.instance = GetModuleHandle(NULL);

        hmodHook = LoadLibrary("Win9xConHook.dll");
        if (hmodHook)
        {
            hhkGetMessage = SetWindowsHookEx(WH_GETMESSAGE,
                (HOOKPROC)GetProcAddress(hmodHook, "GetMsgProc"), hmodHook, 0);
            //hhkCallWndProc = SetWindowsHookEx(WH_CALLWNDPROC,
            //    (HOOKPROC)GetProcAddress(hmodHook, "CallWndProc"), hmodHook, 0);
        }
        
        hThread = CreateThread(NULL, 0, ttyConsoleCtrlThread,
                               (LPVOID)&tty, 0, &tid);
        if (hThread)
        {
            CloseHandle(hThread);
            return TRUE;
        }
    }
    else /* remove */
    {
        HWND child = FindWindowEx(parent, NULL, "ttyConHookChild", NULL);
        if (child)
            SendMessage(child, WM_DESTROY, 0, 0);
        if (hmodHook)
        {
            if (hhkGetMessage) {
                UnhookWindowsHookEx(hhkGetMessage);
                hhkGetMessage = NULL;
            }
            FreeLibrary(hmodHook);
            hmodHook = NULL;
        }
        return TRUE;
    }
    return FALSE;
}


/*
 * Subclass message process for the tty window
 */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    WNDPROC origproc = (WNDPROC) GetProp(hwnd, origwndprop);
    if (!origproc)
        return 0;

    switch (msg)
    {
        case WM_NCDESTROY:
#ifdef DBG
            DbgPrintf("W Proc %08x hwnd:%08x Subclass removed\r\n", 
                      GetCurrentProcessId(), hwnd);
#endif
            is_subclassed = FALSE;
            SetWindowLong(hwnd, GWL_WNDPROC, (LONG)origproc);
            RemoveProp(hwnd, origwndprop);
            break;

        case WM_CLOSE:
        case WM_ENDSESSION:
        case WM_QUERYENDSESSION:
        {
            HWND child = (HWND)GetProp(hwnd, hookwndprop);
#ifdef DBG
            DbgPrintf("W Proc %08x hwnd:%08x msg:%d\r\n", 
                      GetCurrentProcessId(), hwnd, msg);
#endif
            if (!child)
                break;
            return SendMessage(child, msg, wParam, lParam);
        }
    }
    return CallWindowProc(origproc, hwnd, msg, wParam, lParam);
}


int HookProc(int hc, HWND *hwnd, UINT *msg, WPARAM *wParam, LPARAM *lParam)
{
    if (is_tty == -1 && *hwnd) 
    {
        char ttybuf[4];
        HWND htty;
        hwtty = *hwnd;
        while (htty = GetParent(hwtty))
            hwtty = htty;
        is_tty = (GetClassName(hwtty, ttybuf, sizeof(ttybuf)) 
                  && !strcmp(ttybuf, "tty"));
        if (is_tty)
        {
            WNDPROC origproc = (WNDPROC)GetWindowLong(hwtty, GWL_WNDPROC);
            SetProp(hwtty, origwndprop, origproc);
            SetWindowLong(hwtty, GWL_WNDPROC, (LONG)WndProc);
            is_subclassed = TRUE;
#ifdef DBG
            DbgPrintf("W Proc %08x hwnd:%08x Subclassed\r\n", 
                      GetCurrentProcessId(), hwtty);
#endif
        }
#ifdef DBG
        DbgPrintf("H Proc %08x %s %08x\r\n", GetCurrentProcessId(), 
                  is_tty ? "tracking" : "ignoring", hwtty);
#endif
    }

    if (hc >= 0 && is_tty && *hwnd == hwtty)
    {
        if ((*msg == WM_CLOSE)
         || (*msg == WM_ENDSESSION)) {
            DWORD apppid, ttypid = GetCurrentProcessId();
            GetWindowThreadProcessId(*hwnd, &apppid);
#ifdef DBG
            DbgPrintf("H Proc %08x hwnd:%08x owned by %08x msg:%d\r\n", ttypid, *hwnd, apppid, *msg);
#endif
            //*msg = WM_NULL;
            /*
             * Experimental, return 0 or 1 will bypass the next hook and return that
             * value from the hook procedure, -1 continues to call the next hook.
             */
            return -1;
        }
    }
    return -1;
}


/*
 * PostMessage Hook:
 */
LRESULT __declspec(dllexport) CALLBACK GetMsgProc(INT hc, WPARAM wParam, LPARAM lParam)
{
    PMSG pmsg;

    pmsg = (PMSG)lParam;

    if (pmsg) {
        int rv = HookProc(hc, &pmsg->hwnd, &pmsg->message, &pmsg->lParam, &pmsg->wParam);
        if (rv != -1)
            return rv;
    }
    /* 
     * CallNextHookEx apparently ignores the hhook argument, so pass NULL
     */
    return CallNextHookEx(NULL, hc, wParam, lParam);
}


/*
 * SendMessage Hook:
 */
LRESULT __declspec(dllexport) CALLBACK CallWndProc(INT hc, WPARAM wParam, LPARAM lParam)
{
    PCWPSTRUCT pcwps = (PCWPSTRUCT)lParam;
    
    if (pcwps) {
        int rv = HookProc(hc, &pcwps->hwnd, &pcwps->message, &pcwps->wParam, &pcwps->lParam);
        if (rv != -1)
            return rv;
    }
    /* 
     * CallNextHookEx apparently ignores the hhook argument, so pass NULL
     */
    return CallNextHookEx(NULL, hc, wParam, lParam);
}


#ifdef DBG
VOID DbgPrintf(
    LPTSTR fmt,
    ...
    )
{
    va_list marker;
    TCHAR szBuf[256];
    DWORD t;
    HANDLE gDbgOut;

    va_start(marker, fmt);
    wvsprintf(szBuf, fmt, marker);
    va_end(marker);

    gDbgOut = CreateFile("COM1", GENERIC_READ | GENERIC_WRITE, 
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    WriteFile(gDbgOut, szBuf, strlen(szBuf), &t, NULL);
    CloseHandle(gDbgOut);
}
#endif


