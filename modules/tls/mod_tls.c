/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2001 The Apache Software Foundation.  All rights
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

#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"
#include "http_connection.h"
#include "openssl_state_machine.h"
#include "apr_strings.h"
#include "http_protocol.h"
#include "http_log.h"

/* temp */
#include <assert.h>

module AP_MODULE_DECLARE_DATA tls_module;
static const char tls_filter_name[] = "TLSFilter";

typedef struct tls_config_rec
{
    int enabled;
    const char *certificate_file;
    const char *key_file;
} tls_config_rec;

typedef struct tls_filter_ctx
{
    SSLStateMachine *state_machine;
    ap_filter_t *input_filter;
    ap_filter_t *output_filter;
    apr_bucket_brigade *bb_encrypted;     /* encrypted input */
    apr_bucket_brigade *bb_decrypted;     /* decrypted input */
} tls_filter_ctx;

static void *create_tls_server_config(apr_pool_t *p, server_rec *s)
{
    tls_config_rec *tcfg = apr_pcalloc(p, sizeof(*tcfg));

    tcfg->enabled = 0;
    tcfg->certificate_file = tcfg->key_file = NULL;

    return tcfg;
}

static const char *tls_on(cmd_parms *cmd, void *dummy, int arg)
{
    tls_config_rec *tcfg = ap_get_module_config(cmd->server->module_config,
                                                &tls_module);
    tcfg->enabled = arg;
    return NULL;
}

static const char *tls_cert_file(cmd_parms *cmd, void *dummy, const char *arg)
{
    tls_config_rec *tcfg = ap_get_module_config(cmd->server->module_config,
                                                &tls_module);
    tcfg->certificate_file = ap_server_root_relative(cmd->pool, arg);
    
    /* temp */
    tcfg->key_file = tcfg->certificate_file;
    return NULL;
}

static apr_status_t tls_filter_cleanup(void *data)
{
    SSLStateMachine_free((SSLStateMachine *)data);
    return APR_SUCCESS;
}

static int tls_filter_inserter(conn_rec *c)
{
    tls_config_rec *tcfg = ap_get_module_config(c->base_server->module_config,
                                                &tls_module);
    tls_filter_ctx *ctx;

    if (!tcfg->enabled)
        return DECLINED;

    ctx = apr_pcalloc(c->pool, sizeof(*ctx));
    ctx->state_machine = SSLStateMachine_new(tcfg->certificate_file,
                                             tcfg->key_file);

    if (!ctx->state_machine) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->input_filter = ap_add_input_filter(tls_filter_name, ctx, NULL, c);
    ctx->output_filter = ap_add_output_filter(tls_filter_name, ctx, NULL, c);
    ctx->bb_encrypted = apr_brigade_create(c->pool);
    ctx->bb_decrypted = apr_brigade_create(c->pool);

    apr_pool_cleanup_register(c->pool, (void*)ctx->state_machine,
                              tls_filter_cleanup, apr_pool_cleanup_null);

    return OK;
}

static apr_status_t churn_output(tls_filter_ctx *ctx)
{
    apr_bucket_brigade *bb_out = NULL;
    int done;

    do {
        char buf[1024];
        int n;
        apr_bucket *b;

        done = 0;

        if (SSLStateMachine_write_can_extract(ctx->state_machine)) {
            n = SSLStateMachine_write_extract(ctx->state_machine, buf,
                                              sizeof(buf));
            if (n > 0) {
                char *pbuf;

                if (!bb_out)
                    bb_out = apr_brigade_create(ctx->output_filter->c->pool);

                pbuf = apr_pmemdup(ctx->output_filter->c->pool, buf, n);
                b = apr_bucket_pool_create(pbuf, n, 
                                           ctx->output_filter->c->pool);
                APR_BRIGADE_INSERT_TAIL(bb_out, b);
                done = 1;
                /* } else if (n == 0) {
                 x     apr_bucket *b_eos = apr_bucket_create_eos();
                 x     APR_BRIGADE_INSERT_TAIL(bb_out, b_eos);
                 x } 
                 */
            }
            assert(n > 0);
        }
    } while (done);
    
    /* XXX: check for errors */
    if (bb_out) {
        apr_bucket *b;

        /* XXX: it may be possible to not always flush */
        b = apr_bucket_flush_create();
        APR_BRIGADE_INSERT_TAIL(bb_out, b);
        ap_pass_brigade(ctx->output_filter->next, bb_out);
    }

    return APR_SUCCESS;
}

static apr_status_t churn(tls_filter_ctx *ctx, apr_read_type_e readtype, 
                          apr_size_t *readbytes)
{
    ap_input_mode_t mode = (readtype == APR_BLOCK_READ)
                                ? AP_MODE_BLOCKING
                                : AP_MODE_NONBLOCKING;
    apr_bucket *b_in;

    if (APR_BRIGADE_EMPTY(ctx->bb_encrypted)) {
        ap_get_brigade(ctx->input_filter->next, ctx->bb_encrypted, 
                       mode, readbytes);
        if (APR_BRIGADE_EMPTY(ctx->bb_encrypted))
            return APR_EOF;
    }

    APR_BRIGADE_FOREACH(b_in, ctx->bb_encrypted) {
        const char *data;
        apr_size_t len;
        int n;
        char buf[1024];
        apr_status_t ret;

        if (APR_BUCKET_IS_EOS(b_in)) {
            /* XXX: why can't I reuse b_in??? */
            /* Write eof! */
            break;
        }

        /* read filter */
        ret = apr_bucket_read(b_in, &data, &len, readtype);

        APR_BUCKET_REMOVE(b_in);

        if (ret == APR_SUCCESS && len == 0 && readtype == APR_BLOCK_READ)
            ret = APR_EOF;

        if (len == 0) {
            /* Lazy frickin browsers just reset instead of shutting down. */
            if (ret == APR_EOF || APR_STATUS_IS_ECONNRESET(ret)) {
                if (APR_BRIGADE_EMPTY(ctx->bb_decrypted))
                    return APR_EOF;
                else
                    /* Next time around, the incoming brigade will be empty,
                     * so we'll return EOF then
                     */
                    return APR_SUCCESS;
            }
                
            if (readtype != APR_NONBLOCK_READ)
                ap_log_error(APLOG_MARK, APLOG_ERR, ret, NULL,
                             "Read failed in tls_in_filter");
            assert(readtype == APR_NONBLOCK_READ);
            assert(ret == APR_SUCCESS || APR_STATUS_IS_EAGAIN(ret));
            /* In this case, we have data in the output bucket, or we were
             * non-blocking, so returning nothing is fine.
             */
            return APR_SUCCESS;
        }

        assert(len > 0);

        /* write SSL */
        SSLStateMachine_read_inject(ctx->state_machine, data, len);

        n = SSLStateMachine_read_extract(ctx->state_machine, buf, sizeof(buf));
        if (n > 0) {
            apr_bucket *b_out;
            char *pbuf;

            pbuf = apr_pmemdup(ctx->input_filter->c->pool, buf, n);
            /* XXX: should we use a heap bucket instead? Or a transient (in
             * which case we need a separate brigade for each bucket)?
             */
            b_out = apr_bucket_pool_create(pbuf, n, ctx->input_filter->c->pool);
            APR_BRIGADE_INSERT_TAIL(ctx->bb_decrypted, b_out);

            /* Once we've read something, we can move to non-blocking mode
             * (if we weren't already).
             */
            readtype = APR_NONBLOCK_READ;

            /* XXX: deal with EOF! */
            /* } else if (n == 0) {
             x    apr_bucket *b_eos = apr_bucket_create_eos();
             x    APR_BRIGADE_INSERT_TAIL(bb_encrypted, b_eos);
             x }
             */
        }
        assert(n >= 0);

        ret = churn_output(ctx);
        if (ret != APR_SUCCESS)
            return ret;
    }

    return churn_output(ctx);
}

static apr_status_t tls_out_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
    tls_filter_ctx *ctx = f->ctx;
    apr_bucket *b_in;

    APR_BRIGADE_FOREACH(b_in, bb_in) {
        const char *data;
        apr_size_t len;
        apr_status_t ret;

        if (APR_BUCKET_IS_EOS(b_in)) {
            /* XXX: demote to debug */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Got EOS on output");
            SSLStateMachine_write_close(ctx->state_machine);
            /* XXX: dubious - does this always terminate? 
             * Does it return the right thing? 
             */
            for( ; ; ) {
                ret = churn_output(ctx);
                if (ret != APR_SUCCESS)
                    return ret;
                ret = churn(ctx, APR_NONBLOCK_READ, 0);
                if (ret != APR_SUCCESS) {
                    if (ret == APR_EOF)
                        return APR_SUCCESS;
                    else
                        return ret;
                }
            }
            break;
        }

        if (APR_BUCKET_IS_FLUSH(b_in)) {
            /* assume that churn will flush (or already has) 
             * if there's output
             */
            ret = churn(ctx, APR_NONBLOCK_READ, 0);
            if (ret != APR_SUCCESS)
                return ret;
            continue;
        }

        /* read filter */
        apr_bucket_read(b_in, &data, &len, APR_BLOCK_READ);

        /* write SSL */
        SSLStateMachine_write_inject(ctx->state_machine, data, len);

        /* churn the state machine */
        ret = churn_output(ctx);
        if (ret != APR_SUCCESS)
            return ret;
    }

    return APR_SUCCESS;
}

static apr_status_t tls_in_filter(ap_filter_t *f, apr_bucket_brigade *bb_out,
                                  ap_input_mode_t mode, apr_size_t *readbytes)
{
    tls_filter_ctx *ctx = f->ctx;
    apr_read_type_e readtype = (mode == AP_MODE_BLOCKING)
                                    ? APR_BLOCK_READ
                                    : APR_NONBLOCK_READ;
    apr_status_t ret;

    /* XXX: we don't currently support peek 
     * And we don't need to, it should be eaten by the protocol filter!
     */
    assert(mode != AP_MODE_PEEK);

    /* churn the state machine */
    ret = churn(ctx, readtype, readbytes);
    if (ret != APR_SUCCESS)
        return ret;

    /* XXX: shame that APR_BRIGADE_FOREACH doesn't work here */
    while (!APR_BRIGADE_EMPTY(ctx->bb_decrypted)) {
        apr_bucket *b_in = APR_BRIGADE_FIRST(ctx->bb_decrypted);
        APR_BUCKET_REMOVE(b_in);
        APR_BRIGADE_INSERT_TAIL(bb_out, b_in);
    }

    return APR_SUCCESS;
}

static const char *tls_method(const request_rec *r)
{
    tls_config_rec *tcfg =
        ap_get_module_config(r->connection->base_server->module_config,
                             &tls_module);

    if (!tcfg->enabled)
        return NULL;

    return "https";
}

static unsigned short tls_port(const request_rec *r)
{
    tls_config_rec *tcfg =
        ap_get_module_config(r->connection->base_server->module_config,
                             &tls_module);

    if (!tcfg->enabled)
        return 0;

    return 443;
}

static const command_rec tls_cmds[] = 
{
  /* XXX: We should be able to add the filter using AddOutputFilter */
    AP_INIT_FLAG("TLSFilter", tls_on, NULL, RSRC_CONF,
                 "Run TLS/SSL on this host"),
    AP_INIT_TAKE1("TLSCertificateFile", tls_cert_file, NULL, RSRC_CONF,
                 "Set the certificate file for this host"),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    SSLStateMachine_init();

    ap_register_output_filter(tls_filter_name, tls_out_filter,
                              AP_FTYPE_NETWORK);
    ap_register_input_filter(tls_filter_name, tls_in_filter,
                             AP_FTYPE_NETWORK);
    ap_hook_pre_connection(tls_filter_inserter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_default_port(tls_port, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_http_method(tls_method, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA tls_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        /* create per-directory config structure */
    NULL,                        /* merge per-directory config structures */
    create_tls_server_config,    /* create per-server config structure */
    NULL,                        /* merge per-server config structures */
    tls_cmds,                    /* command apr_table_t */
    register_hooks               /* register hooks */
};
