/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
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

/* This debugging define turns on output to COM1, although you better init
 * the port first (even using hyperterm).  It's the only way to catch the
 * goings on within system logoff/shutdown.
 * #define DBG 1
 */

#include <windows.h>

/* Variables used within any process context:
 *  hookwndmsg is a shared message to send Win9xConHook signals
 *  origwndprop is a wndprop atom to store the orig wndproc of the tty
 *  hookwndprop is a wndprop atom to store the hwnd of the hidden child
 *  is_service reminds us to unmark this process on the way out
 */
static UINT hookwndmsg = 0;
static LPCTSTR origwndprop;
static LPCTSTR hookwndprop;
static BOOL is_service = 0;
//static HMODULE hmodThis = NULL;

/* Variables used within the tty processes' context:
 *  is_tty flags this process;  -1 == unknown, 1 == if tty, 0 == if not
 *  hw_tty is the handle of the top level tty in this process context
 *  is_subclassed is toggled to assure DllMain removes the subclass on unload
 *  hmodLock is there to try and prevent this dll from being unloaded if the
 *           hook is removed while we are subclassed
 */
static int is_tty = -1;
static HWND hwtty = NULL;
static BOOL is_subclassed = 0;

// This simply causes a gpfault the moment it tries to FreeLibrary within
// the subclass procedure ... not good.
//static HMODULE hmodLock = NULL;

/* Variables used within the service or console app's context:
 *  hmodHook is the instance handle of this module for registering the hooks
 *  hhkGetMessage is the hook handle for catching Posted messages
 *  hhkGetMessage is the hook handle for catching Sent messages
 *  monitor_hwnd is the invisible window that handles our tty messages
 *  the tty_info strucure is used to pass args into the hidden window's thread
 */
static HMODULE hmodHook = NULL;
static HHOOK hhkGetMessage;
//static HHOOK hhkCallWndProc;
static HWND monitor_hwnd = NULL;

typedef struct {
    PHANDLER_ROUTINE phandler;
    HINSTANCE instance;
    HWND parent;
    INT type;
    LPCSTR name;
} tty_info;

/* These are the GetWindowLong offsets for the hidden window's internal info
 *  gwltty_phandler is the address of the app's HandlerRoutine
 *  gwltty_ttywnd is the tty this hidden window will handle messages from
 */
#define gwltty_phandler 0
#define gwltty_ttywnd 4

/* Forward declaration prototypes for internal functions 
 */
static BOOL CALLBACK EnumttyWindow(HWND wnd, LPARAM retwnd);
static LRESULT WINAPI RegisterWindows9xService(BOOL set_service);
static LRESULT CALLBACK ttyConsoleCtrlWndProc(HWND hwnd, UINT msg, 
                                              WPARAM wParam, LPARAM lParam);
static DWORD WINAPI ttyConsoleCtrlThread(LPVOID tty);
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, 
                                WPARAM wParam, LPARAM lParam);
static int HookProc(int hc, HWND *hwnd, UINT *msg, 
                    WPARAM *wParam, LPARAM *lParam);
#ifdef DBG
static VOID DbgPrintf(LPTSTR fmt, ...);
#endif


/* DllMain is invoked by every process in the entire system that is hooked
 * by our window hooks, notably the tty processes' context, and by the user
 * who wants tty messages (the app).  Keep it light and simple.
 */
BOOL __declspec(dllexport) APIENTRY DllMain(HINSTANCE hModule, ULONG ulReason, 
                                            LPVOID pctx)
{
    if (ulReason == DLL_PROCESS_ATTACH) 
    {
        //hmodThis = hModule;
        if (!hookwndmsg) {
            origwndprop = MAKEINTATOM(GlobalAddAtom("Win9xConHookOrigProc"));
            hookwndprop = MAKEINTATOM(GlobalAddAtom("Win9xConHookThunkWnd"));
            hookwndmsg = RegisterWindowMessage("Win9xConHookMsg");
        }
#ifdef DBG
//        DbgPrintf("H ProcessAttach:%8.8x\r\n", 
//                  GetCurrentProcessId());
#endif
    }
    else if ( ulReason == DLL_PROCESS_DETACH ) 
    {
#ifdef DBG
//        DbgPrintf("H ProcessDetach:%8.8x\r\n", GetCurrentProcessId());                
#endif
        if (monitor_hwnd)
            SendMessage(monitor_hwnd, WM_DESTROY, 0, 0);
        if (is_subclassed) 
            SendMessage(hwtty, hookwndmsg, 0, (LPARAM)hwtty);
        if (hmodHook)
        {
            if (hhkGetMessage) {
                UnhookWindowsHookEx(hhkGetMessage);
                hhkGetMessage = NULL;
            }
            //if (hhkCallWndProc) {
            //    UnhookWindowsHookEx(hhkCallWndProc);
            //    hhkCallWndProc = NULL;
            //}
            FreeLibrary(hmodHook);
            hmodHook = NULL;
        }
        if (is_service)
            RegisterWindows9xService(FALSE);
        if (hookwndmsg) {
            GlobalDeleteAtom((ATOM)origwndprop);
            GlobalDeleteAtom((ATOM)hookwndprop);
            hookwndmsg = 0;
        }
    }
    return TRUE;
}


/*  This group of functions are provided for the service/console app
 *  to register itself a HandlerRoutine to accept tty or service messages
 */


/*  Exported function that creates a Win9x 'service' via a hidden window,
 *  that notifies the process via the HandlerRoutine messages.
 */
BOOL __declspec(dllexport) WINAPI Windows9xServiceCtrlHandler(
        PHANDLER_ROUTINE phandler,
        LPCSTR name)
{
    /* If we have not yet done so */
    FreeConsole();

    if (name)
    {
        DWORD tid;
        HANDLE hThread;
        /* NOTE: this is static so the module can continue to
         * access these args while we go on to other things
         */
        static tty_info tty;
        tty.instance = GetModuleHandle(NULL);
        tty.phandler = phandler;
        tty.parent = NULL;
        tty.name = name;
        tty.type = 2;
        RegisterWindows9xService(TRUE);
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
        if (monitor_hwnd)
            SendMessage(monitor_hwnd, WM_DESTROY, 0, 0);
        RegisterWindows9xService(FALSE);
        return TRUE;
    }
    return FALSE;
}


/*  Exported function that registers a HandlerRoutine to accept missing
 *  Win9x CTRL_EVENTs from the tty window, as NT does without a hassle.
 *  If add is 1 or 2, register the handler, if 2 also mark it as a service.
 *  If add is 0 deregister the handler, and unmark if a service
 */
BOOL __declspec(dllexport) WINAPI FixConsoleCtrlHandler(
        PHANDLER_ROUTINE phandler,
        INT add)
{
    HWND parent;

    if (add)
    {
        HANDLE hThread;
        DWORD tid;
        /* NOTE: this is static so the module can continue to
         * access these args while we go on to other things
         */
        static tty_info tty;
        EnumWindows(EnumttyWindow, (LPARAM)&parent);
        if (!parent) {
#ifdef DBG
            DbgPrintf("A EnumttyWindow failed (%d)\r\n", GetLastError());
#endif
            return FALSE;
        }
        tty.instance = GetModuleHandle(NULL);
        tty.phandler = phandler;
        tty.parent = parent;
        tty.type = add;
        if (add == 2) {
            tty.name = "ttyService";
            RegisterWindows9xService(TRUE);
        }
        else 
            tty.name = "ttyMonitor";
        hThread = CreateThread(NULL, 0, ttyConsoleCtrlThread,
                               (LPVOID)&tty, 0, &tid);
        if (!hThread)
            return FALSE;        
        CloseHandle(hThread);
        hmodHook = LoadLibrary("Win9xConHook.dll");
        if (hmodHook)
        {
            hhkGetMessage = SetWindowsHookEx(WH_GETMESSAGE,
              (HOOKPROC)GetProcAddress(hmodHook, "GetMsgProc"), hmodHook, 0);
            //hhkCallWndProc = SetWindowsHookEx(WH_CALLWNDPROC,
            //  (HOOKPROC)GetProcAddress(hmodHook, "CallWndProc"), hmodHook, 0);
        }        
        return TRUE;
    }
    else /* remove */
    {
        if (monitor_hwnd) {
            SendMessage(monitor_hwnd, WM_DESTROY, 0, 0);
        }
        if (hmodHook)
        {
            if (hhkGetMessage) {
                UnhookWindowsHookEx(hhkGetMessage);
                hhkGetMessage = NULL;
            }
            //if (hhkCallWndProc) {
            //    UnhookWindowsHookEx(hhkCallWndProc);
            //    hhkCallWndProc = NULL;
            //}
            FreeLibrary(hmodHook);
            hmodHook = NULL;
        }
        if (is_service)
            RegisterWindows9xService(FALSE);
        return TRUE;
    }
    return FALSE;
}


/*  The following internal helpers are only used within the app's context
 */

/* ttyConsoleCreateThread is the process that runs within the user app's
 * context.  It creates and pumps the messages of a hidden monitor window,
 * watching for messages from the system, or the associated subclassed tty 
 * window.  Things can happen in our context that can't be done from the
 * tty's context, and visa versa, so the subclass procedure and this hidden
 * window work together to make it all happen.
 */
static DWORD WINAPI ttyConsoleCtrlThread(LPVOID tty)
{
    WNDCLASS wc;
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
    if (((tty_info*)tty)->parent)
        wc.lpszClassName = "ttyConHookChild";
    else
        wc.lpszClassName = "ApacheWin95ServiceMonitor";
        
    if (!RegisterClass(&wc)) { 
#ifdef DBG
        DbgPrintf("A proc %8.8x Error creating class %s (%d)\r\n", 
                  GetCurrentProcessId(), wc.lpszClassName, GetLastError());
#endif
        return 0;
    }

    /* Create an invisible window */
    monitor_hwnd = CreateWindow(wc.lpszClassName, ((tty_info*)tty)->name, 
                                WS_OVERLAPPED & ~WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, 
                                CW_USEDEFAULT, CW_USEDEFAULT, 
                                NULL, NULL, 
                                ((tty_info*)tty)->instance, tty);

    if (!monitor_hwnd) {
#ifdef DBG
        DbgPrintf("A proc %8.8x Error creating window %s %s (%d)\r\n", 
                  GetCurrentProcessId(), wc.lpszClassName, 
                  ((tty_info*)tty)->name, GetLastError());
#endif
        return 0;
    }

    while (GetMessage(&msg, NULL, 0, 0)) 
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    /* Tag again as deleted, just in case we missed WM_DESTROY */
    monitor_hwnd = NULL;
    return 0;
}


/* This is the WndProc procedure for our invisible window.
 * When our subclasssed tty window receives the WM_CLOSE, WM_ENDSESSION,
 * or WM_QUERYENDSESSION messages, the message is dispatched to our hidden
 * window (this message process), and we call the installed HandlerRoutine 
 * that was registered by the app.
 */
static LRESULT CALLBACK ttyConsoleCtrlWndProc(HWND hwnd, UINT msg, 
                                              WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CREATE)
    {
        tty_info *tty = (tty_info*)(((LPCREATESTRUCT)lParam)->lpCreateParams);
        SetWindowLong(hwnd, gwltty_phandler, (LONG)tty->phandler);
        SetWindowLong(hwnd, gwltty_ttywnd, (LONG)tty->parent);
#ifdef DBG
        DbgPrintf("A proc %8.8x created %8.8x %s for tty wnd %8.8x\r\n", 
                  GetCurrentProcessId(), hwnd, 
                  tty->name, tty->parent);
#endif
        if (tty->parent) {
            SetProp(tty->parent, hookwndprop, hwnd);
            PostMessage(tty->parent, hookwndmsg, 
                        tty->type, (LPARAM)tty->parent); 
        }
        return 0;
    }
    else if (msg == WM_DESTROY)
    {
        HWND parent = (HWND)GetWindowLong(hwnd, gwltty_ttywnd);
#ifdef DBG
        DbgPrintf("A proc %8.8x destroyed %8.8x ttyConHookChild\r\n",
                  GetCurrentProcessId(), hwnd);
#endif
        if (parent) {
            RemoveProp(parent, hookwndprop);
            SendMessage(parent, hookwndmsg, 0, (LPARAM)parent); 
        }
        monitor_hwnd = NULL;
    }
    else if (msg == WM_CLOSE)
    {
        PHANDLER_ROUTINE phandler = 
            (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
        LRESULT rv = phandler(CTRL_CLOSE_EVENT);
#ifdef DBG
        DbgPrintf("A proc %8.8x invoked CTRL_CLOSE_EVENT "
                  "returning %d\r\n",
                  GetCurrentProcessId(), rv);
#endif
        if (rv)
            return !rv;
    }
    else if ((msg == WM_QUERYENDSESSION) || (msg == WM_ENDSESSION))
    {
        if (lParam & ENDSESSION_LOGOFF) 
        {
            PHANDLER_ROUTINE phandler = 
                (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
            LRESULT rv = phandler(CTRL_LOGOFF_EVENT);
#ifdef DBG
            DbgPrintf("A proc %8.8x invoked CTRL_LOGOFF_EVENT "
                      "returning %d\r\n",
                      GetCurrentProcessId(), rv);
#endif
            if (rv)
                return ((msg == WM_QUERYENDSESSION) ? rv : !rv);
        }
        else
        {
            PHANDLER_ROUTINE phandler = 
                (PHANDLER_ROUTINE)GetWindowLong(hwnd, gwltty_phandler);
            LRESULT rv = phandler(CTRL_SHUTDOWN_EVENT);
#ifdef DBG
            DbgPrintf("A proc %8.8x invoked CTRL_SHUTDOWN_EVENT "
                      "returning %d\r\n", GetCurrentProcessId(), rv);
#endif
            if (rv)
                return ((msg == WM_QUERYENDSESSION) ? rv : !rv);
        }
    }
    return (DefWindowProc(hwnd, msg, wParam, lParam));
}


/*  The following internal helpers are invoked by the hooked tty and our app
 */

 
/*  Register or deregister the current process as a Windows9x style service.
 *  Experience shows this call is ignored across processes, so the second
 *  arg to RegisterServiceProcess (process group id) is effectively useless.
 */
static LRESULT WINAPI RegisterWindows9xService(BOOL set_service)
{
    static HINSTANCE hkernel;
    static DWORD (WINAPI *register_service_process)(DWORD, DWORD) = NULL;
    BOOL rv;

    if (set_service == is_service)
        return 1;

#ifdef DBG
    DbgPrintf("R %s proc %8.8x as a service\r\n",
              set_service ? "installing" : "removing",
              GetCurrentProcessId());
#endif

    if (!register_service_process)
    {
        /* Obtain a handle to the kernel library */
        hkernel = LoadLibrary("KERNEL32.DLL");
        if (!hkernel)
            return 0;
    
        /* Find the RegisterServiceProcess function */
        register_service_process = (DWORD (WINAPI *)(DWORD, DWORD))
                         GetProcAddress(hkernel, "RegisterServiceProcess");
        if (register_service_process == NULL) {
            FreeLibrary(hkernel);
            return 0;
        }
    }
    
    /* Register this process as a service */
    rv = register_service_process(0, set_service != FALSE);
    if (rv)
        is_service = set_service;
    
    if (!is_service)
    {
        /* Unload the kernel library */
        FreeLibrary(hkernel);
        register_service_process = NULL;
    }
    return rv;
}


/* 
 * This function only works when this process is the active process 
 * (e.g. once it is running a child process, it can no longer determine 
 * which console window is its own.)
 */
static BOOL CALLBACK EnumttyWindow(HWND wnd, LPARAM retwnd)
{
    char tmp[8];
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


/* The remaining code all executes --in the tty's own process context--
 *
 * That means special attention must be paid to what it's doing...
 */

/* Subclass message process for the tty window
 *
 * This code -handles- WM_CLOSE, WM_ENDSESSION and WM_QUERYENDSESSION
 * by dispatching them to the window identified by the hookwndprop
 * property atom set against our window.  Messages are then dispatched
 * to origwndprop property atom we set against the window when we
 * injected this subclass.  This trick did not work with simply a hook.
 */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, 
                                WPARAM wParam, LPARAM lParam)
{
    WNDPROC origproc = (WNDPROC) GetProp(hwnd, origwndprop);
    if (!origproc)
        return 0;

    if (msg == WM_NCDESTROY 
        || (msg == hookwndmsg && !LOWORD(wParam) && (HWND)lParam == hwnd))
    {
        if (is_subclassed) {
#ifdef DBG
            DbgPrintf("W proc %08x hwnd:%08x Subclass removed\r\n", 
                      GetCurrentProcessId(), hwnd);
#endif
            if (is_service)
                RegisterWindows9xService(FALSE);
            SetWindowLong(hwnd, GWL_WNDPROC, (LONG)origproc);
            RemoveProp(hwnd, origwndprop);
            RemoveProp(hwnd, hookwndprop);
            is_subclassed = FALSE;
            //if (hmodLock)
            //    FreeLibrary(hmodLock);
            //hmodLock = NULL;
        }
    }
    else if (msg == WM_CLOSE || msg == WM_ENDSESSION 
                             || msg == WM_QUERYENDSESSION)
    {
        HWND child = (HWND)GetProp(hwnd, hookwndprop);
        if (child) {
#ifdef DBG
            DbgPrintf("W proc %08x hwnd:%08x forwarded msg:%d\r\n", 
                      GetCurrentProcessId(), hwnd, msg);
#endif
            return SendMessage(child, msg, wParam, lParam);
        }
    }
    return CallWindowProc(origproc, hwnd, msg, wParam, lParam);
}


/* HookProc, once installed, is responsible for subclassing the system
 * tty windows.  It generally does nothing special itself, since
 * research indicates that it cannot deal well with the messages we are
 * interested in, that is, WM_CLOSE, WM_QUERYSHUTDOWN and WM_SHUTDOWN
 * of the tty process.
 *
 * Respond and subclass only when a WM_NULL is received by the window.
 */
int HookProc(int hc, HWND *hwnd, UINT *msg, WPARAM *wParam, LPARAM *lParam)
{
    if (is_tty == -1 && *hwnd) 
    {
        char ttybuf[8];
        HWND htty;
        hwtty = *hwnd;
        while (htty = GetParent(hwtty))
            hwtty = htty;
        is_tty = (GetClassName(hwtty, ttybuf, sizeof(ttybuf)) 
                  && !strcmp(ttybuf, "tty"));
#ifdef DBG
        if (is_tty)
            DbgPrintf("H proc %08x tracking hwnd %08x\r\n", 
                      GetCurrentProcessId(), hwtty);
#endif
    }

    if (*msg == hookwndmsg && *wParam && *lParam == (LPARAM)hwtty && is_tty)
    {
        WNDPROC origproc = (WNDPROC)GetWindowLong(hwtty, GWL_WNDPROC);
        //char myname[MAX_PATH];
        //if (GetModuleFileName(hmodThis, myname, sizeof(myname)))
        //    hmodLock = LoadLibrary(myname);        
        SetProp(hwtty, origwndprop, origproc);
        SetWindowLong(hwtty, GWL_WNDPROC, (LONG)WndProc);
        is_subclassed = TRUE;
#ifdef DBG
        DbgPrintf("H proc %08x hwnd:%08x Subclassed\r\n", 
                  GetCurrentProcessId(), hwtty);
#endif
        if (LOWORD(*wParam) == 2)
            RegisterWindows9xService(TRUE);
    }

    return -1;
}


/*
 * PostMessage Hook:
 */
LRESULT __declspec(dllexport) CALLBACK GetMsgProc(INT hc, WPARAM wParam, 
                                                  LPARAM lParam)
{
    PMSG pmsg;

    pmsg = (PMSG)lParam;

    if (pmsg) {
        int rv = HookProc(hc, &pmsg->hwnd, &pmsg->message, 
                          &pmsg->wParam, &pmsg->lParam);
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
LRESULT __declspec(dllexport) CALLBACK CallWndProc(INT hc, WPARAM wParam, 
                                                   LPARAM lParam)
{
    PCWPSTRUCT pcwps = (PCWPSTRUCT)lParam;
    
    if (pcwps) {
        int rv = HookProc(hc, &pcwps->hwnd, &pcwps->message, 
                          &pcwps->wParam, &pcwps->lParam);
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
    static HANDLE mutex;
    va_list marker;
    TCHAR szBuf[256];
    DWORD t;
    HANDLE gDbgOut;

    va_start(marker, fmt);
    wvsprintf(szBuf, fmt, marker);
    va_end(marker);

    if (!mutex)
        mutex = CreateMutex(NULL, FALSE, "Win9xConHookDbgOut");
    WaitForSingleObject(mutex, INFINITE);
    gDbgOut = CreateFile("COM1", GENERIC_READ | GENERIC_WRITE, 0,
                         NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
    WriteFile(gDbgOut, szBuf, strlen(szBuf), &t, NULL);
    CloseHandle(gDbgOut);
    ReleaseMutex(mutex);
}
#endif

#endif /* WIN32 */
