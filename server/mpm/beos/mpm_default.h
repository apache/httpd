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

#ifndef APACHE_MPM_DEFAULT_H
#define APACHE_MPM_DEFAULT_H

/* we use the child (c) as zero in our code... */
#define AP_ID_FROM_CHILD_THREAD(c, t)     t
/* as the child is always zero, just return the id... */
#define AP_CHILD_THREAD_FROM_ID(i)        0 , i

/* Number of threads to spawn off by default --- also, if fewer than
 * this free when the caretaker checks, it will spawn more.
 */
#ifndef DEFAULT_START_THREADS
#define DEFAULT_START_THREADS 10
#endif

#ifdef NO_THREADS
#define DEFAULT_THREADS 1
#endif
#ifndef DEFAULT_THREADS
#define DEFAULT_THREADS 10
#endif

/* The following 2 settings are used to control the number of threads
 * we have available.  Normally the DEFAULT_MAX_FREE_THREADS is set
 * to the same as the HARD_THREAD_LIMIT to avoid churning of starting
 * new threads to replace threads killed off...
 */

/* Maximum number of *free* threads --- more than this, and
 * they will die off.
 */
#ifndef DEFAULT_MAX_FREE_THREADS
#define DEFAULT_MAX_FREE_THREADS HARD_THREAD_LIMIT
#endif

/* Minimum --- fewer than this, and more will be created */
#ifndef DEFAULT_MIN_FREE_THREADS
#define DEFAULT_MIN_FREE_THREADS 1
#endif
                   
/* Where the main/parent process's pid is logged */
#ifndef DEFAULT_PIDLOG
#define DEFAULT_PIDLOG DEFAULT_REL_RUNTIMEDIR "/httpd.pid"
#endif

/*
 * Interval, in microseconds, between scoreboard maintenance.
 */
#ifndef SCOREBOARD_MAINTENANCE_INTERVAL
#define SCOREBOARD_MAINTENANCE_INTERVAL 1000000
#endif

/* Number of requests to try to handle in a single process.  If == 0,
 * the children don't die off.
 */
#ifndef DEFAULT_MAX_REQUESTS_PER_THREAD
#define DEFAULT_MAX_REQUESTS_PER_THREAD 0
#endif

#endif /* AP_MPM_DEFAULT_H */
