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
