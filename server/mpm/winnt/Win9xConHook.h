


/*
 * FixConsoleControlHandler will register a handler routine with the
 * Win9xConHook.dll, creating a hidden window and forwarding the
 * WM_ENDSESSION and WM_CLOSE messages to the registered handler
 * as CTRL_SHUTDOWN_EVENT, CTRL_LOGOFF_EVENT and CTRL_CLOSE_EVENT. 
 */
BOOL WINAPI FixConsoleCtrlHandler(
        PHANDLER_ROUTINE phandler,
        BOOL add);

/*
 * PostMessage Hook:
 */
LRESULT CALLBACK GetMsgProc(INT hc, WPARAM wParam, LPARAM lParam);


/*
 * SendMessage Hook:
 */
LRESULT CALLBACK CallWndProc(INT hc, WPARAM wParam, LPARAM lParam);

