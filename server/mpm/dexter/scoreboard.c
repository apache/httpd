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

#include "apr_strings.h"
#include "ap_config.h" 
#include "httpd.h"
#include "http_log.h"
#include "http_main.h"
#include "http_core.h"
#include "http_config.h"
#include "unixd.h"
#include "http_conf_globals.h"
#include "mpm_status.h"
#include "scoreboard.h"
#include "mpm.h" /* for ap_max_daemons_limit */
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

static scoreboard *ap_scoreboard_image = NULL;

/*****************************************************************
 *
 * Dealing with the scoreboard... a lot of these variables are global
 * only to avoid getting clobbered by the longjmp() that happens when
 * a hard timeout expires...
 *
 * We begin with routines which deal with the file itself... 
 */

#if APR_HAS_SHARED_MEMORY
#include "apr_shmem.h"

static apr_shmem_t *scoreboard_shm = NULL;

apr_status_t ap_cleanup_shared_mem(void *d)
{
    apr_shm_free(scoreboard_shm, ap_scoreboard_image);
    ap_scoreboard_image = NULL;
    apr_shm_destroy(scoreboard_shm);
    return APR_SUCCESS;
}

static void setup_shared_mem(apr_pool_t *p)
{
    char buf[512];
    const char *fname;

    fname = ap_server_root_relative(p, ap_scoreboard_fname);
    if (apr_shm_init(&scoreboard_shm, SCOREBOARD_SIZE + 40, fname, p) != APR_SUCCESS) {
        apr_snprintf(buf, sizeof(buf), "%s: could not open(create) scoreboard",
                    ap_server_argv0);
        perror(buf);
        exit(APEXIT_INIT);
    }
    ap_scoreboard_image = apr_shm_malloc(scoreboard_shm, SCOREBOARD_SIZE);
    if (ap_scoreboard_image == NULL) {
        apr_snprintf(buf, sizeof(buf), "%s: cannot allocate scoreboard",
                    ap_server_argv0);
        perror(buf);
        apr_shm_destroy(scoreboard_shm);
        exit(APEXIT_INIT);
    }
    apr_register_cleanup(p, NULL, ap_cleanup_shared_mem, apr_null_cleanup);
}

void reinit_scoreboard(apr_pool_t *p)
{
    if (ap_scoreboard_image == NULL) {
        setup_shared_mem(p);
    }
    memset(ap_scoreboard_image, 0, SCOREBOARD_SIZE);
}
#endif   /* APR_SHARED_MEM */

/****
 * Above code is shmem code. Below code is interacting with the shmem
 ****/

static int maintain_connection_status = 1;

void ap_dexter_set_maintain_connection_status(int flag) {
    maintain_connection_status = flag;
    return;
}

/* Useful to erase the status of children that might be from previous
 * generations */
void ap_dexter_force_reset_connection_status(long conn_id)
{
    int i;

    for (i = 0; i < STATUSES_PER_CONNECTION; i++) {
        ap_scoreboard_image->table[conn_id][i].key[0] = '\0';
    }
}

void ap_reset_connection_status(long conn_id)
{
    if (maintain_connection_status) {
        ap_dexter_force_reset_connection_status(conn_id);
    }
}

/* Don't mess with the string you get back from this function */
const char *ap_get_connection_status(long conn_id, const char *key)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return "";
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            return ss->value;
        }
    }

    return NULL;
}

apr_array_header_t *ap_get_connections(apr_pool_t *p)
{
    int i;
    apr_array_header_t *connection_list;
    long *array_slot;

    connection_list = apr_make_array(p, 0, sizeof(long));
    /* We assume that there is a connection iff it has an entry in the status
     * table. Connections without any status sound problematic to me, so this
     * is probably for the best. - manoj */
    for (i = 0; i < ap_max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] != '\0') {
            array_slot = apr_push_array(connection_list);
            *array_slot = i;
        }
    }
    return connection_list;
}

apr_array_header_t *ap_get_connection_keys(apr_pool_t *p, long conn_id)
{
    int i = 0;
    status_table_entry *ss;
    apr_array_header_t *key_list;
    char **array_slot;

    key_list = apr_make_array(p, 0, KEY_LENGTH * sizeof(char));
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        array_slot = apr_push_array(key_list);
        *array_slot = apr_pstrdup(p, ss->key);
        i++;
    }
    return key_list;
}

/* Note: no effort is made here to prevent multiple threads from messing with
 * a single connection at the same time. ap_update_connection_status should
 * only be called by the thread that owns the connection */

void ap_update_connection_status(long conn_id, const char *key,
                                 const char *value)
{
    int i = 0;
    status_table_entry *ss;

    if (!maintain_connection_status) return;
    while (i < STATUSES_PER_CONNECTION) {
        ss = &(ap_scoreboard_image->table[conn_id][i]);
        if (ss->key[0] == '\0') {
            break;
        }
        if (0 == strcmp(ss->key, key)) {
            apr_cpystrn(ss->value, value, VALUE_LENGTH);
            return;
        }
	i++;
    }
    /* Not found. Add an entry for this value */
    if (i >= STATUSES_PER_CONNECTION) {
        /* No room. Oh well, not much anyone can do about it. */
        return;
    }
    apr_cpystrn(ss->key, key, KEY_LENGTH);
    apr_cpystrn(ss->value, value, VALUE_LENGTH);
    return;
}

apr_array_header_t *ap_get_status_table(apr_pool_t *p)
{
    int i, j;
    apr_array_header_t *server_status;
    ap_status_table_row_t *array_slot;
    status_table_entry *ss;

    server_status = apr_make_array(p, 0, sizeof(ap_status_table_row_t));

    /* Go ahead and return what's in the connection status table even if we
     * aren't maintaining it. We can at least look at what children from
     * previous generations are up to. */

    for (i = 0; i < ap_max_daemons_limit*HARD_THREAD_LIMIT; i++) {
	if (ap_scoreboard_image->table[i][0].key[0] == '\0')
	    continue;
        array_slot = apr_push_array(server_status);
        array_slot->data = apr_make_table(p, 0);
        array_slot->conn_id = i;
        
        for (j = 0; j < STATUSES_PER_CONNECTION; j++) {
	    ss = &(ap_scoreboard_image->table[i][j]);
            if (ss->key[0] != '\0') {
                apr_table_add(array_slot->data, ss->key, ss->value);
            }
            else {
                break;
            }
        }
    }
    return server_status;
}
