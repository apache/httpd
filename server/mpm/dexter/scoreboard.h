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
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

#ifndef APACHE_SCOREBOARD_H
#define APACHE_SCOREBOARD_H
#include <pthread.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifdef TPF
#include <time.h>
#else
#include <sys/times.h>
#endif /* TPF */

#include "mpm_default.h"	/* For HARD_.*_LIMIT */

/* The generic shared memory chunk code */
void reinit_scoreboard(apr_pool_t *p);

API_EXPORT(void) reopen_scoreboard(apr_pool_t *p);

/* The stuff for Dexter's status table */

#include "mpm_status.h"

void ap_dexter_set_maintain_connection_status(int flag);
void ap_dexter_force_reset_connection_status(long conn_id);
#define KEY_LENGTH 16
#define VALUE_LENGTH 64
typedef struct {
    char key[KEY_LENGTH];
    char value[VALUE_LENGTH];
} status_table_entry;

#define STATUSES_PER_CONNECTION 10

typedef struct {
    status_table_entry
        table[HARD_SERVER_LIMIT*HARD_THREAD_LIMIT][STATUSES_PER_CONNECTION];
} scoreboard;

#define SCOREBOARD_SIZE		sizeof(scoreboard)

API_VAR_EXPORT extern const char *ap_scoreboard_fname;

apr_status_t ap_cleanup_shared_mem(void *d);

#ifdef __cplusplus
}
#endif

#endif	/* !APACHE_SCOREBOARD_H */
