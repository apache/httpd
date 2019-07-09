/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <assert.h>
#include <apr_optional.h>
#include <apr_time.h>
#include <apr_date.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

#include "mod_status.h"

#include "md.h"
#include "md_curl.h"
#include "md_crypt.h"
#include "md_http.h"
#include "md_json.h"
#include "md_status.h"
#include "md_store.h"
#include "md_store_fs.h"
#include "md_log.h"
#include "md_reg.h"
#include "md_util.h"
#include "md_version.h"
#include "md_acme.h"
#include "md_acme_authz.h"

#include "mod_md.h"
#include "mod_md_private.h"
#include "mod_md_config.h"
#include "mod_md_drive.h"
#include "mod_md_status.h"

/**************************************************************************************************/
/* Certificate status */

#define APACHE_PREFIX               "/.httpd/"
#define MD_STATUS_RESOURCE          APACHE_PREFIX"certificate-status"

int md_http_cert_status(request_rec *r)
{
    md_json_t *resp, *j, *mdj, *certj;
    const md_srv_conf_t *sc;
    const md_t *md;
    apr_bucket_brigade *bb;
    apr_status_t rv;
    
    if (!r->parsed_uri.path || strcmp(MD_STATUS_RESOURCE, r->parsed_uri.path))
        return DECLINED;
        
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "requesting status for: %s", r->hostname);
    
    /* We are looking for information about a staged certificate */
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc || !sc->mc || !sc->mc->reg || !sc->mc->certificate_status_enabled) return DECLINED;
    md = md_get_by_domain(sc->mc->mds, r->hostname);
    if (!md) return DECLINED;

    if (r->method_number != M_GET) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "md(%s): status supports only GET", md->name);
        return HTTP_NOT_IMPLEMENTED;
    }
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "requesting status for MD: %s", md->name);

    if (APR_SUCCESS != (rv = md_status_get_md_json(&mdj, md, sc->mc->reg, r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10175)
                      "loading md status for %s", md->name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "status for MD: %s is %s", md->name, md_json_writep(mdj, r->pool, MD_JSON_FMT_INDENT));

    resp = md_json_create(r->pool);
    
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_VALID_UNTIL, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_VALID_UNTIL, NULL), 
                     resp, MD_KEY_VALID_UNTIL, NULL);
    }
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_VALID_FROM, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_VALID_FROM, NULL), 
                     resp, MD_KEY_VALID_FROM, NULL);
    }
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_SERIAL, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_SERIAL, NULL), 
                     resp, MD_KEY_SERIAL, NULL);
    }
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_SHA256_FINGERPRINT, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_SHA256_FINGERPRINT, NULL), 
                     resp, MD_KEY_SHA256_FINGERPRINT, NULL);
    }
    
    if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
        /* copy over the information we want to make public about this:
         *  - when not finished, add an empty object to indicate something is going on
         *  - when a certificate is staged, add the information from that */
        certj = md_json_getj(mdj, MD_KEY_RENEWAL, MD_KEY_CERT, NULL);
        j = certj? certj : md_json_create(r->pool);; 
        md_json_setj(j, resp, MD_KEY_RENEWAL, NULL);
    }
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "md[%s]: sending status", md->name);
    apr_table_set(r->headers_out, "Content-Type", "application/json"); 
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    md_json_writeb(resp, MD_JSON_FMT_INDENT, bb);
    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
    
    return DONE;
}

/**************************************************************************************************/
/* Status hook */

typedef struct {
    apr_pool_t *p;
    const md_mod_conf_t *mc;
    apr_bucket_brigade *bb;
    const char *separator;
} status_ctx;

typedef struct status_info status_info; 

static void add_json_val(status_ctx *ctx, md_json_t *j);

typedef void add_status_fn(status_ctx *ctx, md_json_t *mdj, const status_info *info);

struct status_info {
    const char *label;
    const char *key;
    add_status_fn *fn;
};

static void si_val_status(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *s = "unknown";
    (void)info;
    switch (md_json_getl(mdj, MD_KEY_STATE, NULL)) {
        case MD_S_INCOMPLETE: s = "incomplete"; break;
        case MD_S_EXPIRED_DEPRECATED:
        case MD_S_COMPLETE: s = "ok"; break;
        case MD_S_ERROR: s = "error"; break;
        case MD_S_MISSING_INFORMATION: s = "missing information"; break;
        default: break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);
}

static void si_val_renew_mode(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *s;
    switch (md_json_getl(mdj, info->key, NULL)) {
        case MD_RENEW_MANUAL: s = "manual"; break;
        case MD_RENEW_ALWAYS: s = "always"; break;
        default: s = "auto"; break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);
}


static void si_val_date(status_ctx *ctx, apr_time_t timestamp)
{
    if (timestamp > 0) {
        char ts[128];
        char ts2[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
        ts[len] = '\0';
        apr_strftime(ts2, &len, sizeof(ts2)-1, "%Y-%m-%d", &texp);
        ts2[len] = '\0';
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<span title='%s' style='white-space: nowrap;'>%s</span>", 
                           ts, ts2);
    }
    else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "-");
    }
}

static void si_val_time(status_ctx *ctx, apr_time_t timestamp)
{
    if (timestamp > 0) {
        char ts[128];
        char ts2[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
        ts[len] = '\0';
        apr_strftime(ts2, &len, sizeof(ts2)-1, "%H:%M:%SZ", &texp);
        ts2[len] = '\0';
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<span title='%s' style='white-space: nowrap;'>%s</span>", 
                           ts, ts2);
    }
    else {
        apr_brigade_puts(ctx->bb, NULL, NULL, "-");
    }
}

static void si_val_expires(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *s;
    apr_time_t t;
    
    (void)info;
    s = md_json_dups(ctx->p, mdj, MD_KEY_CERT, MD_KEY_VALID_UNTIL, NULL);
    if (s) {
        t = apr_date_parse_rfc(s);
        si_val_date(ctx, t);
    }
}

static void si_val_valid_from(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *s;
    apr_time_t t;
    
    (void)info;
    s = md_json_dups(ctx->p, mdj, MD_KEY_CERT, MD_KEY_VALID_FROM, NULL);
    if (s) {
        t = apr_date_parse_rfc(s);
        si_val_date(ctx, t);
    }
}
    
static void si_val_props(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *s, *url;
    md_pkey_type_t ptype;
    int i = 0;
    (void)info;

    if (md_json_getb(mdj, MD_KEY_MUST_STAPLE, NULL)) {
        ++i;
        apr_brigade_puts(ctx->bb, NULL, NULL, "must-staple");
    }
    s = md_json_gets(mdj, MD_KEY_RENEW_WINDOW, NULL);
    if (s) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        apr_brigade_printf(ctx->bb, NULL, NULL, "renew-at[%s]", s);
    }
    url = s = md_json_gets(mdj, MD_KEY_CA, MD_KEY_URL, NULL);
    if (s) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        if (!strcmp(LE_ACMEv2_PROD, s)) s = "letsencrypt(v2)";
        else if (!strcmp(LE_ACMEv1_PROD, s)) s = "letsencrypt(v1)";
        else if (!strcmp(LE_ACMEv2_STAGING, s)) s = "letsencrypt(Testv2)";
        else if (!strcmp(LE_ACMEv1_STAGING, s)) s = "letsencrypt(Testv1)";
        
        apr_brigade_printf(ctx->bb, NULL, NULL, "ca=[<a href=\"%s\">%s</a>]", url, s);
    }
    if (md_json_has_key(mdj, MD_KEY_CONTACTS, NULL)) {
        if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
        apr_brigade_puts(ctx->bb, NULL, NULL, "contacts=[");
        add_json_val(ctx, md_json_getj(mdj, MD_KEY_CONTACTS, NULL));
        apr_brigade_puts(ctx->bb, NULL, NULL, "]");
    }
    ptype = md_json_has_key(mdj, MD_KEY_PKEY, MD_KEY_TYPE, NULL)?
            (unsigned)md_json_getl(mdj, MD_KEY_PKEY, MD_KEY_TYPE, NULL) : MD_PKEY_TYPE_DEFAULT; 
    switch (ptype) {
        case MD_PKEY_TYPE_RSA:
            if (i++) apr_brigade_puts(ctx->bb, NULL, NULL, " \n"); 
            apr_brigade_printf(ctx->bb, NULL, NULL, "key[RSA(%u)]", 
                (unsigned)md_json_getl(mdj, MD_KEY_PKEY, MD_PKEY_RSA_BITS_MIN, NULL));
        default:
            break;
    }
}

static void si_val_renewal(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    char buffer[HUGE_STRING_LEN];
    apr_status_t rv;
    int finished, errors;
    apr_time_t t;
    const char *s;
    
    (void)info;
    if (!md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
        return;
    }
    
    finished = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_FINISHED, NULL);
    errors = (int)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_ERRORS, NULL);
    rv = (apr_status_t)md_json_getl(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_STATUS, NULL);
    
    if (rv != APR_SUCCESS) {
        s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_PROBLEM, NULL);
        apr_brigade_printf(ctx->bb, NULL, NULL, "Error[%s]: %s", 
                           apr_strerror(rv, buffer, sizeof(buffer)), s? s : "");
    }
    
    if (finished) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "Finished");
        if (md_json_has_key(mdj, MD_KEY_RENEWAL, MD_KEY_VALID_FROM, NULL)) {
            s = md_json_gets(mdj,  MD_KEY_RENEWAL, MD_KEY_VALID_FROM, NULL);
            t = apr_date_parse_rfc(s);
            apr_brigade_puts(ctx->bb, NULL, NULL, (apr_time_now() >= t)?
                             ", valid since: " : ", activate at: ");
            si_val_time(ctx, t);
        }
        apr_brigade_puts(ctx->bb, NULL, NULL, ".");
    } 
    
    s = md_json_gets(mdj, MD_KEY_RENEWAL, MD_KEY_LAST, MD_KEY_DETAIL, NULL);
    if (s) apr_brigade_puts(ctx->bb, NULL, NULL, s);
    
    errors = (int)md_json_getl(mdj, MD_KEY_ERRORS, NULL);
    if (errors > 0) {
        apr_brigade_printf(ctx->bb, NULL, NULL, ", Had %d errors.", errors);
    } 
    
    s = md_json_gets(mdj,  MD_KEY_RENEWAL, MD_KEY_NEXT_RUN, NULL);
    if (s) {
        t = apr_date_parse_rfc(s);
        apr_brigade_puts(ctx->bb, NULL, NULL, "Next attempt: ");
        si_val_time(ctx, t);
        apr_brigade_puts(ctx->bb, NULL, NULL, ".");
    }
}

static void si_val_remote_check(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *fingerprint;
    
    (void)info;
    fingerprint = md_json_gets(mdj, MD_KEY_CERT, MD_KEY_SHA256_FINGERPRINT, NULL);
    if (fingerprint) {
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<a href=\"https://censys.io/certificates/%s\">censys.io</a> ", 
                           fingerprint);
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<a href=\"https://crt.sh?q=%s\">crt.sh</a> ", fingerprint);
    }
}

const status_info status_infos[] = {
    { "Name", MD_KEY_NAME, NULL },
    { "Domains", MD_KEY_DOMAINS, NULL },
    { "Status", MD_KEY_STATUS, si_val_status },
    { "Valid", MD_KEY_VALID_FROM, si_val_valid_from },
    { "Expires", MD_KEY_VALID_UNTIL, si_val_expires },
    { "Renew", MD_KEY_RENEW_MODE, si_val_renew_mode },
    { "Check@", MD_KEY_SHA256_FINGERPRINT, si_val_remote_check },
    { "Configuration", MD_KEY_MUST_STAPLE, si_val_props },
    { "Renewal",  MD_KEY_NOTIFIED, si_val_renewal },
};

static int json_iter_val(void *data, size_t index, md_json_t *json)
{
    status_ctx *ctx = data;
    if (index) apr_brigade_puts(ctx->bb, NULL, NULL, ctx->separator);
    add_json_val(ctx, json);
    return 1;
}

static void add_json_val(status_ctx *ctx, md_json_t *j)
{
    if (!j) return;
    else if (md_json_is(MD_JSON_TYPE_ARRAY, j, NULL)) {
        md_json_itera(json_iter_val, ctx, j, NULL);
    }
    else if (md_json_is(MD_JSON_TYPE_INT, j, NULL)) {
        md_json_writeb(j, MD_JSON_FMT_COMPACT, ctx->bb);
    }
    else if (md_json_is(MD_JSON_TYPE_STRING, j, NULL)) {
        apr_brigade_puts(ctx->bb, NULL, NULL, md_json_gets(j, NULL));
    }
    else if (md_json_is(MD_JSON_TYPE_OBJECT, j, NULL)) {
        md_json_writeb(j, MD_JSON_FMT_COMPACT, ctx->bb);
    }
}

static void add_status_cell(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    if (info->fn) {
        info->fn(ctx, mdj, info);
    }
    else {
        add_json_val(ctx, md_json_getj(mdj, info->key, NULL));
    }
}

static int add_md_row(void *baton, apr_size_t index, md_json_t *mdj)
{
    status_ctx *ctx = baton;
    int i;
    
    apr_brigade_printf(ctx->bb, NULL, NULL, "<tr class=\"%s\">", (index % 2)? "odd" : "even");
    for (i = 0; i < (int)(sizeof(status_infos)/sizeof(status_infos[0])); ++i) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "<td>");
        add_status_cell(ctx, mdj, &status_infos[i]);
        apr_brigade_puts(ctx->bb, NULL, NULL, "</td>");
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, "</tr>");
    return 1;
}

static int md_name_cmp(const void *v1, const void *v2)
{
    return strcmp((*(const md_t**)v1)->name, (*(const md_t**)v2)->name);
}

int md_status_hook(request_rec *r, int flags)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;
    int i, html;
    status_ctx ctx;
    apr_array_header_t *mds;
    md_json_t *jstatus, *jstock;
    
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc) return DECLINED;
    mc = sc->mc;
    if (!mc || !mc->server_status_enabled) return DECLINED;

    html = !(flags & AP_STATUS_SHORT);
    ctx.p = r->pool;
    ctx.mc = mc;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ctx.separator = " ";

    mds = apr_array_copy(r->pool, mc->mds);
    qsort(mds->elts, (size_t)mds->nelts, sizeof(md_t *), md_name_cmp);

    if (!html) {
        apr_brigade_puts(ctx.bb, NULL, NULL, "ManagedDomains: ");
        if (mc->mds->nelts > 0) {
            md_status_take_stock(&jstock, mds, mc->reg, r->pool);
            apr_brigade_printf(ctx.bb, NULL, NULL, "total=%d, ok=%d renew=%d errored=%d ready=%d",
                                (int)md_json_getl(jstock, MD_KEY_TOTAL, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_COMPLETE, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_RENEWING, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_ERRORED, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_READY, NULL));
        } 
        else {
            apr_brigade_puts(ctx.bb, NULL, NULL, "[]"); 
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "\n"); 
    }
    else if (mc->mds->nelts > 0) {
        md_status_get_json(&jstatus, mds, mc->reg, r->pool);
        apr_brigade_puts(ctx.bb, NULL, NULL, 
                         "<hr>\n<h2>Managed Domains</h2>\n<table class='md_status'><thead><tr>\n");
        for (i = 0; i < (int)(sizeof(status_infos)/sizeof(status_infos[0])); ++i) {
            apr_brigade_puts(ctx.bb, NULL, NULL, "<th>");
            apr_brigade_puts(ctx.bb, NULL, NULL, status_infos[i].label);
            apr_brigade_puts(ctx.bb, NULL, NULL, "</th>");
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "</tr>\n</thead><tbody>");
        md_json_itera(add_md_row, &ctx, jstatus, MD_KEY_MDS, NULL);
        apr_brigade_puts(ctx.bb, NULL, NULL, "</td></tr>\n</tbody>\n</table>\n");
    }

    ap_pass_brigade(r->output_filters, ctx.bb);
    apr_brigade_cleanup(ctx.bb);
    
    return OK;
}

/**************************************************************************************************/
/* Status handler */

int md_status_handler(request_rec *r)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;
    apr_array_header_t *mds;
    md_json_t *jstatus;
    apr_bucket_brigade *bb;
    const md_t *md;
    const char *name;

    if (strcmp(r->handler, "md-status")) {
        return DECLINED;
    }

    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc) return DECLINED;
    mc = sc->mc;
    if (!mc) return DECLINED;

    if (r->method_number != M_GET) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "md-status supports only GET");
        return HTTP_NOT_IMPLEMENTED;
    }
    
    jstatus = NULL;
    md = NULL;
    if (r->path_info && r->path_info[0] == '/' && r->path_info[1] != '\0') {
        name = strrchr(r->path_info, '/') + 1;
        md = md_get_by_name(mc->mds, name);
        if (!md) md = md_get_by_domain(mc->mds, name);
    }
    
    if (md) {
        md_status_get_md_json(&jstatus, md, mc->reg, r->pool);
    }
    else {
        mds = apr_array_copy(r->pool, mc->mds);
        qsort(mds->elts, (size_t)mds->nelts, sizeof(md_t *), md_name_cmp);
        md_status_get_json(&jstatus, mds, mc->reg, r->pool);
    }

    if (jstatus) {
        apr_table_set(r->headers_out, "Content-Type", "application/json"); 
        bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        md_json_writeb(jstatus, MD_JSON_FMT_INDENT, bb);
        ap_pass_brigade(r->output_filters, bb);
        apr_brigade_cleanup(bb);
        
        return DONE;
    }
    return DECLINED;
}
