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

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"

API_VAR_EXPORT module echo_module;

typedef struct
    {
    int bEnabled;
    } EchoConfig;

static void *create_echo_server_config(apr_pool_t *p,server_rec *s)
    {
    EchoConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);

    pConfig->bEnabled=0;

    return pConfig;
    }

static const char *echo_on(cmd_parms *cmd, void *dummy, const char *arg)
    {
    EchoConfig *pConfig=ap_get_module_config(cmd->server->module_config,
					     &echo_module);
    pConfig->bEnabled=1;

    return NULL;
    }

static int process_echo_connection(conn_rec *c)
    {
    char buf[1024];
    EchoConfig *pConfig=ap_get_module_config(c->base_server->module_config,
					     &echo_module);

    if(!pConfig->bEnabled)
	return DECLINED;

    for( ; ; )
	{
	apr_ssize_t r, w;
        (void) ap_bread(c->client,buf,sizeof buf,&r);
	if(r <= 0)
	    break;
	(void) ap_bwrite(c->client,buf,r, &w);
	if(w != r)
	    break;
	ap_bflush(c->client);
	}
    return OK;
    }

static const command_rec echo_cmds[] = 
{
    AP_INIT_RAW_ARGS("ProtocolEcho", echo_on, NULL, RSRC_CONF,
                     "Run an echo server on this host"),
    { NULL }
};

static void register_hooks(void)
{
    ap_hook_process_connection(process_echo_connection,NULL,NULL,AP_HOOK_MIDDLE);
}

API_VAR_EXPORT module echo_module = {
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-directory config structure */
    NULL,			/* merge per-directory config structures */
    create_echo_server_config,	/* create per-server config structure */
    NULL,			/* merge per-server config structures */
    echo_cmds,			/* command apr_table_t */
    NULL,			/* handlers */
    register_hooks		/* register hooks */
};
