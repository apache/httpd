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

#ifndef AP_WIN9XCONHOOK_H
#define AP_WIN9XCONHOOK_H

#ifdef WIN32

/* Windows9xServiceCtrlHandler registers a handler routine, frees the
 * console window, and registers this process as a service in Win9x.
 * It creats a hidden window of class "ApacheWin95ServiceMonitor"
 * and titled by the name passed, which passes the WM_SHUTDOWN message 
 * through the given HandlerRoutine's CTRL_SHUTDOWN event.
 * Call with name of NULL to remove the Service handler.
 */
BOOL WINAPI Windows9xServiceCtrlHandler(PHANDLER_ROUTINE phandler, LPCSTR name);


/* FixConsoleControlHandler registers a handler routine with the
 * Win9xConHook.dll, creating a hidden window and forwarding the
 * WM_ENDSESSION and WM_CLOSE messages to the given HandlerRoutine
 * as CTRL_SHUTDOWN_EVENT, CTRL_LOGOFF_EVENT and CTRL_CLOSE_EVENT. 
 * The application should still use SetConsoleCtrlHandler to grab
 * the CTRL_BREAK_EVENT and CTRL_C_EVENT, if desired.
 */
BOOL WINAPI FixConsoleCtrlHandler(PHANDLER_ROUTINE phandler, BOOL add);


/*
 * Exported PostMessage Hook, never use this directly:
 *
 * LRESULT CALLBACK GetMsgProc(INT hc, WPARAM wParam, LPARAM lParam);
 */


/*
 * Exported SendMessage Hook, never use this directly:
 *
 * LRESULT CALLBACK CallWndProc(INT hc, WPARAM wParam, LPARAM lParam);
 */

#endif /* WIN32 */

#endif AP_WIN9XCONHOOK_H
