/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
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

#ifndef SERVICE_H
#define SERVICE_H

#ifdef WIN32

/* BIG RED WARNING: exit() is mapped to allow us to capture the exit
 * status.  This header must only be included from modules linked into
 * the ApacheCore.dll - since it's a horrible behavior to exit() from
 * any module outside the main() block, and we -will- assume it's a
 * fatal error.  No dynamically linked module will ever be able to find
 * the real_exit_code, and _will_ GP fault if it tries this macro.
 */

#define exit(status) ((exit)((real_exit_code==2) ? (real_exit_code = (status)) \
                                                 : ((real_exit_code = 0), (status))))
extern int real_exit_code;
void hold_console_open_on_error(void);

int service_main(int (*main_fn)(int, char **), int argc, char **argv);
int service95_main(int (*main_fn)(int, char **), int argc, char **argv,
		   char *display_name);
void service_set_status(int status);
void service_cd();
char *get_service_name(char *display_name);
char *get_display_name(char *service_name);
BOOL isProcessService();
BOOL isValidService(char *display_name);
void InstallService(pool *p, char *display_name, int argc, char **argv, int reconfig);
void RemoveService(char *display_name);
int send_signal_to_service(char *display_name, char *sig, 
                           int argc, char **argv);
BOOL isWindowsNT(void);
void ap_start_console_monitor(void);
void ap_start_child_console(int is_child_of_service);

#endif /* WIN32 */

#endif /* SERVICE_H */
