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
 */

#ifndef AP_MMN_H
#define AP_MMN_H

/**
 * @package Multi-Processing Module library
 */

/*
    The MPM, "multi-processing model" provides an abstraction of the
    interface with the OS for distributing incoming connections to
    threads/process for processing.  http_main invokes the MPM, and
    the MPM runs until a shutdown/restart has been indicated.
    The MPM calls out to the apache core via the ap_process_connection
    function when a connection arrives.

    The MPM may or may not be multithreaded.  In the event that it is
    multithreaded, at any instant it guarantees a 1:1 mapping of threads
    ap_process_connection invocations.  

    Note: In the future it will be possible for ap_process_connection
    to return to the MPM prior to finishing the entire connection; and
    the MPM will proceed with asynchronous handling for the connection;
    in the future the MPM may call ap_process_connection again -- but
    does not guarantee it will occur on the same thread as the first call.

    The MPM further guarantees that no asynchronous behaviour such as
    longjmps and signals will interfere with the user code that is
    invoked through ap_process_connection.  The MPM may reserve some
    signals for its use (i.e. SIGUSR1), but guarantees that these signals
    are ignored when executing outside the MPM code itself.  (This
    allows broken user code that does not handle EINTR to function
    properly.)

    The suggested server restart and stop behaviour will be "graceful".
    However the MPM may choose to terminate processes when the user
    requests a non-graceful restart/stop.  When this occurs, the MPM kills
    all threads with extreme prejudice, and destroys the pchild pool.
    User cleanups registered in the pchild apr_pool_t will be invoked at
    this point.  (This can pose some complications, the user cleanups
    are asynchronous behaviour not unlike longjmp/signal... but if the
    admin is asking for a non-graceful shutdown, how much effort should
    we put into doing it in a nice way?)

    unix/posix notes:
    - The MPM does not set a SIGALRM handler, user code may use SIGALRM.
	But the preferred method of handling timeouts is to use the
	timeouts provided by the BUFF/iol abstraction.
    - The proper setting for SIGPIPE is SIG_IGN, if user code changes it
        for any of their own processing, it must be restored to SIG_IGN
	prior to executing or returning to any apache code.
    TODO: add SIGPIPE debugging check somewhere to make sure its SIG_IGN
*/

/**
 * This is the function that MPMs must create.  This function is responsible
 * for controlling the parent and child processes.  It will run until a 
 * restart/shutdown is indicated.
 * @param pconf the configuration pool, reset before the config file is read
 * @param plog the log pool, reset after the config file is read
 * @param server_conf the global server config.
 * @return 1 for shutdown 0 otherwise.
 * @deffunc int ap_mpm_run(apr_pool_t *pconf, apr_pool_t *plog, server_rec *server_conf)
 */
API_EXPORT(int) ap_mpm_run(apr_pool_t *pconf, apr_pool_t *plog, server_rec *server_conf);

/**
 * predicate indicating if a graceful stop has been requested ...
 * used by the connection loop 
 * @return 1 if a graceful stop has been requested, 0 otherwise
 * @deffunc int ap_graceful_stop_signalled*void)
 */
API_EXPORT(int) ap_graceful_stop_signalled(void);

/**
 * ap_start_shutdown() and ap_start_restart() is a function to initiate 
 * shutdown without relying on signals. 
 *
 * This should only be called from the parent process itself, since the
 * parent process will use the shutdown_pending and restart_pending variables
 * to determine whether to shutdown or restart. The child process should
 * call signal_parent() directly to tell the parent to die -- this will
 * cause neither of those variable to be set, which the parent will
 * assume means something serious is wrong (which it will be, for the
 * child to force an exit) and so do an exit anyway.
 * @deffunc void ap_start_shutdown(void)
 */

API_EXPORT(void) ap_start_shutdown(void);

#endif
