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
#include "md_ocsp.h"
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

    rv = md_status_get_md_json(&mdj, md, sc->mc->reg, sc->mc->ocsp, r->pool);
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(10204)
                      "loading md status for %s", md->name);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "status for MD: %s is %s", md->name, md_json_writep(mdj, r->pool, MD_JSON_FMT_INDENT));

    resp = md_json_create(r->pool);
    
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_UNTIL, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_UNTIL, NULL), 
                     resp, MD_KEY_VALID, MD_KEY_UNTIL, NULL);
    }
    if (md_json_has_key(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_FROM, NULL)) {
        md_json_sets(md_json_gets(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_FROM, NULL), 
                     resp, MD_KEY_VALID, MD_KEY_FROM, NULL);
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
    apr_time_t until;
    (void)info;
    switch (md_json_getl(mdj, info->key, NULL)) {
        case MD_S_INCOMPLETE: s = "incomplete"; break;
        case MD_S_EXPIRED_DEPRECATED:
        case MD_S_COMPLETE:
            until = md_json_get_time(mdj, MD_KEY_CERT, MD_KEY_VALID, MD_KEY_UNTIL, NULL);
            s = (!until || until > apr_time_now())? "good" : "expired"; 
            break;
        case MD_S_ERROR: s = "error"; break;
        case MD_S_MISSING_INFORMATION: s = "missing information"; break;
        default: break;
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, s);
}

static void si_val_url(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *url, *s;
    apr_uri_t uri_parsed;

    
    s = url = md_json_gets(mdj, info->key, NULL);
    if (!url) return;
    if (!strcmp(LE_ACMEv2_PROD, url)) {
        s = "Let's Encrypt";
    }
    else if (!strcmp(LE_ACMEv2_STAGING, url)) {
        s = "Let's Encrypt (staging)";
    }
    else if (!strcmp(LE_ACMEv1_PROD, url)) {
        s = "Let's Encrypt (v1)";
    }
    else if (!strcmp(LE_ACMEv1_STAGING, url)) {
        s = "Let's Encrypt (v1,staging)";
    }
    else if (APR_SUCCESS == apr_uri_parse(ctx->p, url, &uri_parsed)) {
        s = uri_parsed.hostname;
        
    }
    apr_brigade_printf(ctx->bb, NULL, NULL, "<a href='%s'>%s</a>", 
                       ap_escape_html2(ctx->p, url, 1), 
                       ap_escape_html2(ctx->p, s, 1));
}

static void print_date(apr_bucket_brigade *bb, apr_time_t timestamp, const char *title)
{
    if (timestamp > 0) {
        char ts[128];
        char ts2[128];
        apr_time_exp_t texp;
        apr_size_t len;
        
        apr_time_exp_gmt(&texp, timestamp);
        apr_strftime(ts, &len, sizeof(ts2)-1, "%Y-%m-%d", &texp);
        ts[len] = '\0';
        if (!title) {
            apr_strftime(ts2, &len, sizeof(ts)-1, "%Y-%m-%dT%H:%M:%SZ", &texp);
            ts2[len] = '\0';
            title = ts2;
        }
        apr_brigade_printf(bb, NULL, NULL, 
                           "<span title='%s' style='white-space: nowrap;'>%s</span>", 
                           ap_escape_html2(bb->p, title, 1), ts);
    }
}

static void print_time(apr_bucket_brigade *bb, const char *label, apr_time_t t)
{
    apr_time_t now;
    const char *pre, *post, *sep;
    char ts[APR_RFC822_DATE_LEN];
    char ts2[128];
    apr_time_exp_t texp;
    apr_size_t len;
    apr_interval_time_t delta;
    
    if (t == 0) {
        /* timestamp is 0, we use that for "not set" */
        return;
    }
    apr_time_exp_gmt(&texp, t);
    now = apr_time_now();
    pre = post = "";
    sep = (label && strlen(label))? " " : "";
    delta = 0;
    apr_rfc822_date(ts, t);
    if (t > now) {
        delta = t - now;
        pre = "in ";
    }
    else {
        delta = now - t;
        post = " ago";
    }
    if (delta >= (4 * apr_time_from_sec(MD_SECS_PER_DAY))) {
        apr_strftime(ts2, &len, sizeof(ts2)-1, "%Y-%m-%d", &texp);
        ts2[len] = '\0';
        apr_brigade_printf(bb, NULL, NULL, "%s%s<span title='%s' "
                           "style='white-space: nowrap;'>%s</span>", 
                           label, sep, ts, ts2); 
    }
    else {
        apr_brigade_printf(bb, NULL, NULL, "%s%s<span title='%s'>%s%s%s</span>", 
                           label, sep, ts, pre, md_duration_roughly(bb->p, delta), post); 
    }
}

static void si_val_valid_time(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *sfrom, *suntil, *sep, *title;
    apr_time_t from, until;
    
    sep = NULL;
    sfrom = md_json_gets(mdj, info->key, MD_KEY_FROM, NULL);
    from = sfrom? apr_date_parse_rfc(sfrom) : 0;
    suntil = md_json_gets(mdj, info->key, MD_KEY_UNTIL, NULL);
    until = suntil?apr_date_parse_rfc(suntil) : 0;
    
    if (from > apr_time_now()) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "from ");
        print_date(ctx->bb, from, sfrom);
        sep = " ";
    }
    if (until) {
        if (sep) apr_brigade_puts(ctx->bb, NULL, NULL, sep);
        apr_brigade_puts(ctx->bb, NULL, NULL, "until ");
        title = sfrom? apr_psprintf(ctx->p, "%s - %s", sfrom, suntil) : suntil;
        print_date(ctx->bb, until, title);
    }
}

static void si_add_header(status_ctx *ctx, const status_info *info)
{
    const char *html = ap_escape_html2(ctx->p, info->label, 1);
    apr_brigade_printf(ctx->bb, NULL, NULL, "<th class=\"%s\">%s</th>", html, html);
}

static void si_val_cert_valid_time(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    md_json_t *jcert;
    status_info sub = *info;
    
    sub.key = MD_KEY_VALID;
    jcert = md_json_getj(mdj, info->key, NULL);
    if (jcert) si_val_valid_time(ctx, jcert, &sub);
}

static void si_val_ca_url(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    md_json_t *jcert;
    status_info sub = *info;
    
    sub.key = MD_KEY_URL;
    jcert = md_json_getj(mdj, info->key, NULL);
    if (jcert) si_val_url(ctx, jcert, &sub);
}
    
static void print_job_summary(apr_bucket_brigade *bb, md_json_t *mdj, const char *key, 
                              const char *separator)
{
    char buffer[HUGE_STRING_LEN];
    apr_status_t rv;
    int finished, errors;
    apr_time_t t;
    const char *s, *line;
    
    if (!md_json_has_key(mdj, key, NULL)) {
        return;
    }
    
    finished = (int)md_json_getl(mdj, key, MD_KEY_FINISHED, NULL);
    errors = (int)md_json_getl(mdj, key, MD_KEY_ERRORS, NULL);
    rv = (apr_status_t)md_json_getl(mdj, key, MD_KEY_LAST, MD_KEY_STATUS, NULL);
    
    line = separator? separator : "";

    if (rv != APR_SUCCESS) {
        s = md_json_gets(mdj, key, MD_KEY_LAST, MD_KEY_PROBLEM, NULL);
        line = apr_psprintf(bb->p, "%s Error[%s]: %s", line, 
                           apr_strerror(rv, buffer, sizeof(buffer)), s? s : "");
    }
    
    if (finished) {
        line = apr_psprintf(bb->p, "%s finished successfully.", line);
    } 
    else {
        s = md_json_gets(mdj, key, MD_KEY_LAST, MD_KEY_DETAIL, NULL);
        if (s) line = apr_psprintf(bb->p, "%s %s", line, s);
    }
    
    errors = (int)md_json_getl(mdj, MD_KEY_ERRORS, NULL);
    if (errors > 0) {
        line = apr_psprintf(bb->p, "%s (%d retr%s) ", line, 
            errors, (errors > 1)? "y" : "ies");
    } 
    
    apr_brigade_puts(bb, NULL, NULL, line);

    t = md_json_get_time(mdj, key, MD_KEY_NEXT_RUN, NULL);
    if (t > apr_time_now() && !finished) {
        print_time(bb, "\nNext run", t);
    }
    else if (!strlen(line)) {
        apr_brigade_puts(bb, NULL, NULL, "\nOngoing...");
    }
}

static void si_val_activity(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    apr_time_t t;
    
    (void)info;
    if (md_json_has_key(mdj, MD_KEY_RENEWAL, NULL)) {
        print_job_summary(ctx->bb, mdj, MD_KEY_RENEWAL, NULL);
        return;
    }
    
    t = md_json_get_time(mdj, MD_KEY_RENEW_AT, NULL);
    if (t > apr_time_now()) {
        print_time(ctx->bb, "Renew", t);
    }
    else if (t) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "Pending");
    }
    else if (MD_RENEW_MANUAL == md_json_getl(mdj, MD_KEY_RENEW_MODE, NULL)) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "Manual renew");
    }
}

static void si_val_remote_check(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    const char *fingerprint;
    
    (void)info;
    if (ctx->mc->cert_check_name && ctx->mc->cert_check_url) {
        fingerprint = md_json_gets(mdj, MD_KEY_CERT, MD_KEY_SHA256_FINGERPRINT, NULL);
        apr_brigade_printf(ctx->bb, NULL, NULL, 
                           "<a href=\"%s%s\">%s</a> ", 
                           ctx->mc->cert_check_url, fingerprint, ctx->mc->cert_check_name);
    }
}

static void si_val_stapling(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    (void)info;
    if (!md_json_getb(mdj, MD_KEY_STAPLING, NULL)) return;
    apr_brigade_puts(ctx->bb, NULL, NULL, "on");
}

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
    else if (md_json_is(MD_JSON_TYPE_BOOL, j, NULL)) {
        apr_brigade_puts(ctx->bb, NULL, NULL, md_json_getb(j, NULL)? "on" : "off");
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

static const status_info status_infos[] = {
    { "Domain", MD_KEY_NAME, NULL },
    { "Names", MD_KEY_DOMAINS, NULL },
    { "Status", MD_KEY_STATE, si_val_status },
    { "Valid", MD_KEY_CERT, si_val_cert_valid_time },
    { "CA", MD_KEY_CA, si_val_ca_url },
    { "Stapling", MD_KEY_STAPLING, si_val_stapling },
    { "Check@", MD_KEY_SHA256_FINGERPRINT, si_val_remote_check },
    { "Activity",  MD_KEY_NOTIFIED, si_val_activity },
};

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

int md_domains_status_hook(request_rec *r, int flags)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;
    int i, html;
    status_ctx ctx;
    apr_array_header_t *mds;
    md_json_t *jstatus, *jstock;
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "server-status for managed domains, start");
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
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "no-html summary");
        apr_brigade_puts(ctx.bb, NULL, NULL, "Managed Certificates: ");
        if (mc->mds->nelts > 0) {
            md_status_take_stock(&jstock, mds, mc->reg, r->pool);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "got JSON summary");
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
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "html table");
        md_status_get_json(&jstatus, mds, mc->reg, mc->ocsp, r->pool);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "got JSON status");
        apr_brigade_puts(ctx.bb, NULL, NULL, 
                         "<hr>\n<h3>Managed Certificates</h3>\n<table class='md_status'><thead><tr>\n");
        for (i = 0; i < (int)(sizeof(status_infos)/sizeof(status_infos[0])); ++i) {
            si_add_header(&ctx, &status_infos[i]);
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "</tr>\n</thead><tbody>");
        md_json_itera(add_md_row, &ctx, jstatus, MD_KEY_MDS, NULL);
        apr_brigade_puts(ctx.bb, NULL, NULL, "</td></tr>\n</tbody>\n</table>\n");
    }

    ap_pass_brigade(r->output_filters, ctx.bb);
    apr_brigade_cleanup(ctx.bb);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "server-status for managed domains, end");
    
    return OK;
}

static void si_val_ocsp_activity(status_ctx *ctx, md_json_t *mdj, const status_info *info)
{
    apr_time_t t;
    
    (void)info;
    t = md_json_get_time(mdj,  MD_KEY_RENEW_AT, NULL);
    print_time(ctx->bb, "Refresh", t);
    print_job_summary(ctx->bb, mdj, MD_KEY_RENEWAL, ": ");
}

static const status_info ocsp_status_infos[] = {
    { "Domain", MD_KEY_DOMAIN, NULL },
    { "Certificate ID", MD_KEY_ID, NULL },
    { "OCSP Status", MD_KEY_STATUS, NULL },
    { "Stapling Valid", MD_KEY_VALID, si_val_valid_time },
    { "Responder", MD_KEY_URL, si_val_url },
    { "Activity",  MD_KEY_NOTIFIED, si_val_ocsp_activity },
};

static int add_ocsp_row(void *baton, apr_size_t index, md_json_t *mdj)
{
    status_ctx *ctx = baton;
    int i;
    
    apr_brigade_printf(ctx->bb, NULL, NULL, "<tr class=\"%s\">", (index % 2)? "odd" : "even");
    for (i = 0; i < (int)(sizeof(ocsp_status_infos)/sizeof(ocsp_status_infos[0])); ++i) {
        apr_brigade_puts(ctx->bb, NULL, NULL, "<td>");
        add_status_cell(ctx, mdj, &ocsp_status_infos[i]);
        apr_brigade_puts(ctx->bb, NULL, NULL, "</td>");
    }
    apr_brigade_puts(ctx->bb, NULL, NULL, "</tr>");
    return 1;
}

int md_ocsp_status_hook(request_rec *r, int flags)
{
    const md_srv_conf_t *sc;
    const md_mod_conf_t *mc;
    int i, html;
    status_ctx ctx;
    md_json_t *jstatus, *jstock;
    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "server-status for ocsp stapling, start");
    sc = ap_get_module_config(r->server->module_config, &md_module);
    if (!sc) return DECLINED;
    mc = sc->mc;
    if (!mc || !mc->server_status_enabled) return DECLINED;

    html = !(flags & AP_STATUS_SHORT);
    ctx.p = r->pool;
    ctx.mc = mc;
    ctx.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ctx.separator = " ";

    if (!html) {
        apr_brigade_puts(ctx.bb, NULL, NULL, "Managed Staplings: ");
        if (md_ocsp_count(mc->ocsp) > 0) {
            md_ocsp_get_summary(&jstock, mc->ocsp, r->pool);
            apr_brigade_printf(ctx.bb, NULL, NULL, "total=%d, good=%d revoked=%d unknown=%d",
                                (int)md_json_getl(jstock, MD_KEY_TOTAL, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_GOOD, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_REVOKED, NULL), 
                                (int)md_json_getl(jstock, MD_KEY_UNKNOWN, NULL));
        } 
        else {
            apr_brigade_puts(ctx.bb, NULL, NULL, "[]"); 
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "\n"); 
    }
    else if (md_ocsp_count(mc->ocsp) > 0) {
        md_ocsp_get_status_all(&jstatus, mc->ocsp, r->pool);
        apr_brigade_puts(ctx.bb, NULL, NULL, 
                         "<hr>\n<h3>Managed Staplings</h3>\n<table class='md_ocsp_status'><thead><tr>\n");
        for (i = 0; i < (int)(sizeof(ocsp_status_infos)/sizeof(ocsp_status_infos[0])); ++i) {
            si_add_header(&ctx, &ocsp_status_infos[i]);
        }
        apr_brigade_puts(ctx.bb, NULL, NULL, "</tr>\n</thead><tbody>");
        md_json_itera(add_ocsp_row, &ctx, jstatus, MD_KEY_OCSPS, NULL);
        apr_brigade_puts(ctx.bb, NULL, NULL, "</td></tr>\n</tbody>\n</table>\n");
    }

    ap_pass_brigade(r->output_filters, ctx.bb);
    apr_brigade_cleanup(ctx.bb);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "server-status for ocsp stapling, end");
    
    return OK;
}

/**************************************************************************************************/
/* Status handlers */

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
        md_status_get_md_json(&jstatus, md, mc->reg, mc->ocsp, r->pool);
    }
    else {
        mds = apr_array_copy(r->pool, mc->mds);
        qsort(mds->elts, (size_t)mds->nelts, sizeof(md_t *), md_name_cmp);
        md_status_get_json(&jstatus, mds, mc->reg, mc->ocsp, r->pool);
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

