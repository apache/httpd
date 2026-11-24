/* Copyright 2019 greenbytes GmbH (https://www.greenbytes.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

#include <apr_lib.h>
#include <apr_buckets.h>
#include <apr_getopt.h>
#include <apr_hash.h>
#include <apr_strings.h>

#include "md.h"
#include "md_acme.h"
#include "md_acme_acct.h"
#include "md_acme_authz.h"
#include "md_json.h"
#include "md_http.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_store.h"
#include "md_util.h"
#include "md_cmd.h"
#include "md_cmd_acme.h"

/**************************************************************************************************/
/* command: acme newreg */

static apr_status_t cmd_acme_newreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    apr_array_header_t *contacts;
    md_t *md;
    int i;
    
    contacts = apr_array_make(ctx->p, 5, sizeof(const char *));
    for (i = 0; i < ctx->argc; ++i) {
        APR_ARRAY_PUSH(contacts, const char *) = md_util_schemify(ctx->p, ctx->argv[i], "mailto");
    }
    if (apr_is_empty_array(contacts)) {
        return usage(cmd, "newreg needs at least one contact email as argument");
    }

    md = md_create_empty(ctx->p);
    md->contacts = contacts;
    md->ca_agreement = ctx->tos;

    rv = md_acme_acct_register(ctx->acme, ctx->store, md, ctx->p);
    if (APR_SUCCESS != rv) goto leave;
    /* check if we can read it back, only then it "exists" */
    rv = md_acme_acct_update(ctx->acme);
    if (APR_SUCCESS != rv) goto leave;
    rv = md_acme_save_acct(ctx->acme, ctx->p, ctx->store); 
    if (APR_SUCCESS != rv) goto leave;
    fprintf(stdout, "registered: %s\n", md_acme_acct_id_get(ctx->acme));
leave:
    if (APR_SUCCESS != rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, ctx->p, "register new account");
    }
    return rv;
}

static md_cmd_t AcmeNewregCmd = {
    "newreg", MD_CTX_ACME, 
    NULL, cmd_acme_newreg, MD_NoOptions, NULL,
    "newreg contact-uri [contact-uri...]",
    "register a new account at ACME server with given contact uri (email)",
};

/**************************************************************************************************/
/* command: acme agree */

static apr_status_t acct_agree_tos(md_cmd_ctx *ctx, const char *name, 
                                   const char *tos, apr_pool_t *p) 
{
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = md_acme_use_acct(ctx->acme, ctx->store, ctx->p, name))) {
        if (!tos) {
            tos = "accepted";
        }
        rv = md_acme_agree(ctx->acme, ctx->p, tos);
        if (rv == APR_SUCCESS) {
            rv = md_acme_save_acct(ctx->acme, ctx->p, ctx->store); 
            fprintf(stdout, "agreed terms-of-service: %s\n", md_acme_acct_url_get(ctx->acme));
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "agree to terms-of-service %s", tos);
        }
    }
    else if (APR_ENOENT == rv) {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "unknown account: %s", name);
    }

    return rv;
}

static apr_status_t cmd_acme_agree(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    (void)cmd;
    for (i = 0; i < ctx->argc; ++i) {
        rv = acct_agree_tos(ctx, ctx->argv[i], ctx->tos, ctx->p);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeAgreeCmd = {
    "agree", MD_CTX_STORE|MD_CTX_ACME, 
    NULL, cmd_acme_agree, MD_NoOptions, NULL,
    "agree account",
    "agree to ACME terms of service",
};

/**************************************************************************************************/
/* command: acme validate */

static apr_status_t acct_validate(md_cmd_ctx *ctx, const char *name, apr_pool_t *p) 
{
    apr_status_t rv;
    
    if (APR_SUCCESS == (rv = md_acme_use_acct(ctx->acme, ctx->store, ctx->p, name))) {
        fprintf(stdout, "account valid: %s\n", name);
    }
    else if (APR_ENOENT == rv) {
        fprintf(stderr, "unknown account: %s", name);
    }
    else {
        md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "validating account: %s", name);
    }
    return rv;
}

static apr_status_t cmd_acme_validate(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    (void)cmd;
    for (i = 0; i < ctx->argc; ++i) {
        rv = acct_validate(ctx, ctx->argv[i], ctx->p);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeValidateCmd = {
    "validate", MD_CTX_STORE|MD_CTX_ACME, 
    NULL, cmd_acme_validate, MD_NoOptions, NULL,
    "validate account",
    "validate account existence",
};

/**************************************************************************************************/
/* command: acme delreg */

static apr_status_t acme_delreg(md_cmd_ctx *ctx, const char *name, apr_pool_t *p) 
{
    apr_status_t rv;
    
    if (ctx->acme) {
        if (APR_SUCCESS == (rv = md_acme_use_acct(ctx->acme, ctx->store, ctx->p, name))) {
            rv = md_acme_acct_deactivate(ctx->acme, ctx->p);
            if (rv == APR_SUCCESS) {
                fprintf(stdout, "deleted: %s\n", name);
                rv = md_acme_save_acct(ctx->acme, ctx->p, ctx->store); 
            }
            else {
                md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "delete account");
            }
        }
        else if (APR_ENOENT == rv) {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "unknown account: %s", name);
        }
        else {
            md_log_perror(MD_LOG_MARK, MD_LOG_ERR, rv, p, "loading account: %s", name);
        }
    }
    else if (ctx->store) {
        rv = md_reg_delete_acct(ctx->reg, ctx->p, name);
    }
    else {
        rv = APR_EGENERAL;
    }
    return rv;
}

static apr_status_t cmd_acme_delreg(md_cmd_ctx *ctx, const md_cmd_t *cmd)
{
    apr_status_t rv = APR_SUCCESS;
    int i;
    
    (void)cmd;
    for (i = 0; i < ctx->argc; ++i) {
        rv = acme_delreg(ctx, ctx->argv[i], ctx->p);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

static md_cmd_t AcmeDelregCmd = {
    "delreg", MD_CTX_STORE|MD_CTX_REG, 
    NULL, cmd_acme_delreg, MD_NoOptions, NULL,
    "delreg account",
    "delete an existing ACME account",
};

/**************************************************************************************************/
/* command: acme */

static const md_cmd_t *AcmeSubCmds[] = {
    &AcmeNewregCmd,
    &AcmeDelregCmd,
    &AcmeAgreeCmd,
    &AcmeValidateCmd,
    NULL
};

md_cmd_t MD_AcmeCmd = {
    "acme", MD_CTX_STORE,  
    NULL, NULL, MD_NoOptions, AcmeSubCmds,
    "acme cmd [opts] [args]", 
    "play with the ACME server", 
};
