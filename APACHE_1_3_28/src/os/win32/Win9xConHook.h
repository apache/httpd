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