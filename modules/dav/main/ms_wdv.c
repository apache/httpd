#include "apr_strings.h"
#include "apr_lib.h"

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"

#include "mod_dav.h"

/*
 * Extended error codes, from MS-WDV section 6
 * This is a subset of codes defined in MS-WEBDAVE section 2.2.3
 */
#define DAV_DOC_CHECKED_OUT             0x0009000E
#define DAV_CHECKOUT_REQUIRED           0x00090075
#define DAV_BAD_FILETYPE_NO_URL         0x0009006F
#define DAV_SHTML_REQUEST_TOO_LONG      0x0006000A
#define DAV_FORMS_AUTH_NOT_BROWSER      0x000E0098
#define DAV_VIRUS_INFECTED_UL           0x00960004
#define DAV_VIRUS_INFECTED_BLOCKED_DL   0x00960009
#define DAV_VIRUS_DELETED_DL            0x00960008
#define DAV_BAD_CHARS_IN_URL            0x00090070
#define DAV_NO_RENAME_TO_THICKET_FOLDER 0x00090071
#define DAV_URL_TOO_LONG                0x00090068
#define DAV_OVER_QUOTA                  0x00090063

/*
 * Cope with MS behavior on DELETE:
 * If: (<locktoken>) is changed into If: <uri> (<locktoken>)
 */
static void delete_if_fixup(request_rec *r)
{
    const char *if_hdr;
    const char *cp;
    apr_size_t len;

    if ((if_hdr =  apr_table_get(r->headers_in, "If")) == NULL)
        goto out;

    /* check for parenthesis enclosed value */
    len = strlen(if_hdr);
    if (if_hdr[0] != '(' || if_hdr[len - 1]!= ')')
        goto out;

    for (cp = if_hdr; *cp; cp++) {
        if (*cp == ')' && *(cp + 1))
            goto out;
    }

    if_hdr = apr_psprintf(r->pool, "<%s> %s", r->uri, if_hdr);
    apr_table_set(r->headers_in, "If", if_hdr);

out:
    return;
}

/*
 * Ms-Echo-Request and Ms-Echo-Reply headers are specified
 * in MS-WDV sections 2.2.7 and 2.2.8
 */
static dav_error *mswdv_echo(request_rec *r)
{
    const char *value;

    if ((value = apr_table_get(r->headers_in, "Ms-Echo-Request")) != NULL)
        apr_table_set(r->headers_out, "Ms-Echo-Reply",  value);

    return NULL;
}


static const char *get_lock_owner(request_rec *r, dav_lock *lock)
{
    while (lock) {
        if (lock->auth_user) {
            break;
        }
        lock = lock->next;
    }

    return lock->auth_user;
}


static const char *mswdv_urlencode(request_rec *r, const char *str)
{
    const char *ip = str;
    char *output;
    char *op;

    output = apr_palloc(r->pool, 3 * strlen(str) + 1);
    op = output;

    for (ip = str; *ip; ip++) {
        if (apr_isalnum(*ip)) {
            *op++ = *ip;
        } else {
            char msb = (*ip >> 4);
            char lsb = (*ip & 0x0f);
            *op++ = '%';
            *op++ = msb > 10 ? 'A' + msb - 10 : '0' +msb;
            *op++ = lsb > 10 ? 'A' + lsb - 10 : '0' +lsb;
        }
    }
    *op++ = '\0';

    return (const char *)output;
}

static void mswdv_err_checked_out(request_rec *r, const char *owner)
{
    const char *msg;

    msg = apr_psprintf(r->pool, "Resource already locked by %s",
                       owner ? owner : "anonymous");
    msg = mswdv_urlencode(r, msg);

    apr_table_set(r->err_headers_out,
                  "X-MSDAVEXT_ERROR",
                  apr_psprintf(r->pool,
                               "%d; %s", DAV_DOC_CHECKED_OUT, msg));
}

static dav_error *check_locked_by_other(request_rec *r)
{
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_lockdb *lockdb = NULL;
    dav_resource *resource;
    dav_lock *lock = NULL;
    const char *owner = NULL;
    dav_error *err = NULL;

    if ((err = dav_get_resource(r, 0, 0, &resource)) != NULL)
        goto out;

    /* dav_lock_query reads R/W in dav_fs_save_lock_record() */
    if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL)
        goto out;

    if ((err = dav_lock_query(lockdb, resource, &lock)) != NULL)
        goto out;

    if (!lock)
        goto out;

    owner = get_lock_owner(r, lock);
    if ((owner && r->user && strcmp(owner, r->user) != 0) ||
        (owner && !r->user) || (!owner && r->user))
       mswdv_err_checked_out(r, owner);

    /* Let lock method fail the request */

out:
    (*lockdb->hooks->close_lockdb)(lockdb);

    return err;
}

/*
 * Adding lock headers to existing commands is specified
 * in MS-WDV section 3.2.5.2
 */
static dav_error *mswdv_combined_lock(request_rec *r)
{
    const char *lock_token_hdr;
    const char *lock_timeout_hdr;
    dav_locktoken *lock_token;
    time_t lock_timeout = 0;
    dav_error *err = NULL;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    dav_lockdb *lockdb = NULL;
    dav_resource *resource;
    dav_lock *lock = NULL;
    const char *owner = NULL;
    dav_lock *newlock = NULL;
    /* conditions */
    int timeout_zero = 0;
    int token_match = 0;
    int lock_exists = 0;
    /* action */
    const char *failmsg = NULL;
    int http_error = HTTP_BAD_REQUEST;
    enum { ERROR, LOCK, UNLOCK, REFRESH, PASS } action = ERROR;

    lock_token_hdr = apr_table_get(r->headers_in, "Lock-Token");
    lock_timeout_hdr = apr_table_get(r->headers_in, "X-MSDAVEXTLockTimeout");

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "%s Lock-Token = \"%s\" X-MSDAVEXTLockTimeout = \"%s\"",
                  __func__, lock_token_hdr, lock_timeout_hdr);

    /*
     * Strip brackets if present. They should be present, but MS-WDV
     * section 4.5 suggests using Lock-Token without brakets.
     */
    if (lock_token_hdr) {
        apr_size_t len = strlen(lock_token_hdr);

        if (lock_token_hdr[0] == '<' || lock_token_hdr[len - 1] == '>')
            lock_token_hdr = apr_pstrndup(r->pool, lock_token_hdr + 1, len - 2);
    }

    if (lock_timeout_hdr) {
        if (strcmp(lock_timeout_hdr, "Second-0") == 0)
            timeout_zero = 1;
        lock_timeout = dav_get_timeout_string(r, lock_timeout_hdr);
    }

    /* Check MS-WDV section 3.2.5.2 for specified behaviors */

    /*
     * First handle behaviors that do not use lock database
     */
    if (r->method_number == M_GET ||
        r->method_number == M_POST) {
        if (lock_token_hdr && !lock_timeout_hdr)
            goto out;
    }

    if (!lock_token_hdr && lock_timeout_hdr && timeout_zero) {
         failmsg = "Unlock operation requires a lock token.";
         goto done;
    }

    /*
     * Determine is token_match, lock_exists and owner
     */
    if ((err = dav_get_resource(r, 0, 0, &resource)) != NULL)
        goto out;

    /* dav_lock_query reads R/W in dav_fs_save_lock_record() */
    if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL)
        goto out;

    if ((err = dav_lock_query(lockdb, resource, &lock)) != NULL)
        goto out;

    if (lock) {
        lock_exists = 1;
        owner = get_lock_owner(r, lock);
    }

    if (lock_token_hdr) {
        if ((err = (*locks_hooks->parse_locktoken)(r->pool, lock_token_hdr,
                                                    &lock_token)) != NULL)
            goto out;

        if ((err = (*locks_hooks->find_lock)(lockdb, resource, lock_token,
                                             0, &lock)) != NULL)
            goto out;

        if (lock)
            token_match = 1;

    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "%s lock_exists = %d, owner = \"%s\", "
                  "token_match = %d, lock_timeout = %" APR_TIME_T_FMT
                  ", timeout_zero = %d",
                  __func__, lock_exists, owner ? owner : "-", token_match,
                  lock_timeout, timeout_zero);

    /* This implements the table from  MS-WDV section 3.2.5.2 */
    if (r->method_number == M_GET ||
         r->method_number == M_POST) {

        if (lock_token_hdr && !lock_timeout_hdr) {
            action = PASS;
            goto done;
        }

        if (lock_token_hdr && lock_timeout_hdr) {
            if (!token_match) {
                failmsg = "Provided lock token does not match.";
                if (lock_exists) {
                    http_error = HTTP_LOCKED;
                    mswdv_err_checked_out(r, owner);
                } else {
                    http_error = HTTP_FORBIDDEN;
                }
                goto done;
            }

            if (!lock_exists) {
                failmsg = "Refresh or unlock operation on unlocked resource.";
                goto done;
            }

            if (!timeout_zero) {
                action = REFRESH;
                goto done;
            }

            if (timeout_zero) {
                action = UNLOCK;
                goto done;
            }

            /* NOTREACHED */
        }

        if (!lock_token_hdr && lock_timeout_hdr) {
            if (lock_exists) {
                failmsg = "Lock operation on an already locked resource.";
                http_error = HTTP_LOCKED;
                mswdv_err_checked_out(r, owner);
                goto done;
            }

            if (timeout_zero) {
                failmsg = "Lock operation with immediate timeout.";
                goto done;
            }

            if (!lock_exists) {
                action = LOCK;
                goto done;
            }
        }

        if (!lock_token_hdr && !lock_timeout_hdr) {
            action = PASS;
            goto done;
        }
    }

    if (r->method_number == M_PUT) {
        if (lock_token_hdr && !lock_timeout_hdr) {
            if (!token_match) {
                failmsg = "Provided lock token does not match.";
                if (lock_exists) {
                    http_error = HTTP_LOCKED;
                    mswdv_err_checked_out(r, owner);
                } else {
                    http_error = HTTP_FORBIDDEN;
                }
                goto done;
            }

            if (!lock_exists) {
                failmsg = "PUT with lock on an unlocked resource.";
                goto done;
            }

            if (token_match && lock_exists) {
                action = PASS;
                goto done;
            }
        }

        if (lock_token_hdr && lock_timeout_hdr) {
            if (!token_match) {
                failmsg = "Provided lock token does not match";
                if (lock_exists) {
                    http_error = HTTP_LOCKED;
                    mswdv_err_checked_out(r, owner);
                } else {
                    http_error = HTTP_FORBIDDEN;
                }
                goto done;
            }

            if (!lock_exists) {
                failmsg = "PUT with lock on an unlocked resource";
                goto done;
            }

            if (!timeout_zero) {
                action = REFRESH;
                goto done;
            }

            if (timeout_zero) {
                action = UNLOCK;
                goto done;
            }
            /* NOTREACHED */
        }


        if (!lock_token_hdr && lock_timeout_hdr) {
            if (lock_exists) {
                failmsg = "Lock operation on already locked resource.";
                http_error = HTTP_LOCKED;
                mswdv_err_checked_out(r, owner);
                goto done;
            }

            if (timeout_zero) {
                failmsg = "Lock operation with immediate timeout.";
                goto done;
            }

            if (!lock_exists) {
                action = LOCK;
                goto done;
            }
        }

        if (!lock_token_hdr && !lock_timeout_hdr) {
                action = PASS;
                goto done;
        }
    }

done:
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "%s failmsg = \"%s\", action = %s%s%s%s%s",
                  __func__, failmsg,
                  action == LOCK ? "LOCK" : "",
                  action == UNLOCK ? "UNLOCK" : "",
                  action == REFRESH ? "REFRESH" : "",
                  action == ERROR ? "ERROR" : "",
                  action == PASS ? "PASS" : "");

    if (failmsg) {
         err = dav_new_error(r->pool, http_error, 0, 0, failmsg);
         goto out;
    }

    switch (action) {
    case PASS:
        if (lock_token_hdr) {
            /* Add a If: lock header to palcate further processing */
            apr_table_setn(r->headers_in, "If",
                           apr_psprintf(r->pool, "(<%s>)", lock_token_hdr));
        }
        break;
    case LOCK: {
        dav_response *dontcare;

        if ((err = (*locks_hooks->create_lock)(lockdb, resource,
                                               &newlock)) != NULL)
            goto out;

        newlock->depth = DAV_INFINITY;
        newlock->timeout = lock_timeout;
        newlock->type = DAV_LOCKTYPE_WRITE;
        newlock->scope = DAV_LOCKSCOPE_EXCLUSIVE;
        newlock->auth_user = apr_pstrdup(r->pool, r->user);
        newlock->owner = apr_psprintf(r->pool,
                                      "<ns0:owner xmlns:ns0=\"DAV:\">"
                                          "<ns0:href>%s</ns0:href>"
                                      "</ns0:owner>",
                                      r->user ? r->user : "anonymous");
        if ((err = dav_add_lock(r, resource, lockdb, newlock,
                                &dontcare)) != NULL)
            goto out;

        break;
    }

    case UNLOCK:
        if ((err = (*locks_hooks->remove_lock)(lockdb, resource,
                                                lock_token)) != NULL)
             goto out;

        break;

    case REFRESH: {
        const dav_locktoken_list ltl = { lock_token, NULL };

        if ((err = (*locks_hooks->refresh_locks)(lockdb, resource, &ltl,
                                                 lock_timeout,
                                                 &newlock)) != NULL)
            goto out;

        break;
    }

    case ERROR: /* FALLTHROUGH */
    default:
        /* NOTREACHED */
        err = dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                             "Unexpected X-MSDAVEXT combined lock action.");
        goto out;
        break;
    }

    if (newlock) {
        /*
         * MS-WDV section 4.5 suggests to send a lock token without
         * brackets, which is at odds with standards.
         */
        apr_table_setn(r->headers_out, "Lock-Token",
                       (*locks_hooks->format_locktoken)(r->pool,
                                                        newlock->locktoken));

        apr_table_setn(r->headers_out, "X-MSDAVEXTLockTimeout",
                       newlock->timeout == DAV_TIMEOUT_INFINITE ?
                       "Infinite" :
                       apr_psprintf(r->pool, "Second-%" APR_TIME_T_FMT,
                                      newlock->timeout - time(NULL)));

        /* Add a If: lock header to palcate further PUT processing */
        apr_table_setn(r->headers_in, "If",
            apr_pstrcat(r->pool, "(<",
                       (*locks_hooks->format_locktoken)(r->pool,
                                                        newlock->locktoken),
                        ">)", NULL));
    }


out:
    if (lockdb)
        (*lockdb->hooks->close_lockdb)(lockdb);

    return err;
}

/*
 * Combined PROPFIND is specified in MS-WDV sections 2.2.1 and 2.2.5
 */
static dav_error *mswdv_combined_propfind(request_rec *r)
{
    apr_bucket_brigade *bbsub;
    apr_bucket_brigade *bb;
    ap_filter_t *f;
    request_rec *rr = NULL;
    apr_off_t length;
    apr_status_t status;
    int ret;

    bbsub = apr_brigade_create(r->pool, r->output_filters->c->bucket_alloc);

    rr = ap_sub_req_method_uri("PROPFIND", r->uri, r, r->output_filters);
    if (!rr || rr->status != HTTP_OK)
        return dav_new_error(r->pool,
                             rr ? rr->status : HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                             "X-DAVMSEXT PROPFIND subrequest lookup failed");

    f = ap_add_output_filter("DAV_MSWDV_OUT", bbsub, rr, rr->connection);
    if (!f)
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                             "DAV_MSWDV_OUT filter not found");

    if ((ret = ap_run_sub_req(rr)) != OK) {
        char *errmsg = apr_psprintf(r->pool,
                                    "X-DAVMSEXT PROPFIND status %d",
                                    ret);
        return dav_new_error(r->pool, rr->status, 0, 0, errmsg);
    }

    ap_remove_output_filter(f);

    if ((status = apr_brigade_length(bbsub, 1, &length)) != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, status,
                             "read response error");

    bb = apr_brigade_create(r->pool,r->output_filters->c->bucket_alloc);

    apr_brigade_printf(bb, NULL, NULL,
                       "%016" APR_UINT64_T_HEX_FMT, length);

    APR_BRIGADE_CONCAT(bb, bbsub);

    ap_destroy_sub_req(rr);

    rr = ap_sub_req_lookup_uri(r->uri, r, r->output_filters);
    if (!rr || rr->status != HTTP_OK)
        return dav_new_error(r->pool,
                             rr ? rr->status : HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                             "X-DAVMSEXT GET subrequest lookup failed");

    if (rr->filename == NULL || rr->finfo.filetype != APR_REG)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, 0,
                             "Not a plain file");

    apr_brigade_printf(bb, NULL, NULL,
                       "%016" APR_UINT64_T_HEX_FMT, rr->finfo.size);

    ap_set_content_type(r, "multipart/MSDAVEXTPrefixEncoded");

    ap_pass_brigade(r->output_filters, bb);

    ap_destroy_sub_req(rr);

    return NULL;
}

/*
 * Combined PROPPATCH is specified in MS-WDV sections 2.2.1 and 2.2.5
 */
static dav_error *mswdv_combined_proppatch(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_status_t status;
    apr_size_t len = 16;
    apr_off_t proppatch_len;
    char proppatch_len_str[16 + 1];
    char *proppatch_data;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    status = ap_get_brigade(r->input_filters, bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            len);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "error reading PROPPATCH part ldength");

    status = apr_brigade_flatten(bb, proppatch_len_str, &len);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, status,
                             "error reading input");

    if (len != 16)
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, status,
                             "Unexpected PROPPATCH part length");

    proppatch_len_str[16] = '\0';

    status = apr_strtoff(&proppatch_len, proppatch_len_str, NULL, 16);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "Bad PROPPATCH part length");

    apr_brigade_destroy(bb);

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    status = ap_get_brigade(r->input_filters, bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            proppatch_len);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "Error reading PROPPATCH part");

    /*
     * For file creation, the PROPATCH subrequest must be done after
     * the PUT, otherwise the file does not exist yet. This mean we
     * need to copy the PROPPATCH data to perform subrequest in
     * dav_mswdv_postprocessing().
     */
    proppatch_data = apr_palloc(r->pool, proppatch_len);

    len = proppatch_len;
    status = apr_brigade_flatten(bb, proppatch_data, &len);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "Error flattening PROPPATCH part");

    apr_table_setn(r->notes, "dav_mswdv_proppatch_data", proppatch_data);

    apr_brigade_destroy(bb);

    /* skip file length to give the file to plain PUT processing */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    status = ap_get_brigade(r->input_filters, bb,
                            AP_MODE_READBYTES, APR_BLOCK_READ,
                            16);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "Error reading PUT part length");

    apr_table_setn(r->headers_in, "Content-Type", "application/octet-stream");

    return NULL;
}

DAV_DECLARE(int) dav_mswdv_preprocessing(request_rec *r)
{
    const char *hdr;
    dav_error *err = NULL;

    /* MS-WDV extensions need X-MSDAVEXT even on an error */
    if (r->method_number == M_OPTIONS) {
        apr_table_setn(r->headers_out, "X-MSDAVEXT", "1");
        apr_table_setn(r->err_headers_out, "X-MSDAVEXT", "1");
    }

    /* Remove tailing # */
    if (r->method_number != M_GET && r->method_number != M_POST)
        r->parsed_uri.fragment = NULL;

    if (r->main)
        goto out;

    if (apr_table_get(r->headers_in, "Ms-Echo-Request")) {
        if ((err = mswdv_echo(r)) != NULL)
            goto out;
    }

    if ((apr_table_get(r->headers_in, "Lock-Token") ||
         apr_table_get(r->headers_in, "X-MSDAVEXTLockTimeout")) &&
        (r->method_number == M_GET ||
         r->method_number == M_POST ||
         r->method_number == M_PUT)) {
        if ((err = mswdv_combined_lock(r)) != NULL)
            goto out;
    }

    if ((hdr = apr_table_get(r->headers_in, "X-MSDAVEXT")) != NULL) {
        if (!strcmp(hdr, "PROPFIND") &&
            (r->method_number == M_GET ||
             r->method_number == M_POST ||
             r->method_number == M_PUT)) {
            if ((err = mswdv_combined_propfind(r)) != NULL)
                goto out;
        }

        if (!strcmp(hdr, "PROPPATCH") &&
            r->method_number == M_PUT)
            if ((err = mswdv_combined_proppatch(r)) != NULL)
                goto out;
    }

    if (r->method_number == M_DELETE)
        delete_if_fixup(r);

    if (r->method_number == M_LOCK ||
        r->method_number == M_MOVE ||
        r->method_number == M_PUT ||
        r->method_number == M_DELETE) {
            if ((err = check_locked_by_other(r)) != NULL)
                goto out;
    }

out:
    if (err)
        return dav_handle_err(r, err, NULL);

    return OK;
}

DAV_DECLARE(dav_error *)dav_mswdv_postprocessing(request_rec *r)
{
    dav_error *err = NULL;
    const char *proppatch_data;
    apr_bucket_brigade *bbsub;
    apr_bucket *b;
    request_rec *rr;
    ap_filter_t *f;
    apr_status_t status;
    int ret;

    if (r->method_number != M_PUT)
        goto out;

    proppatch_data = apr_table_get(r->notes, "dav_mswdv_proppatch_data");
    if (proppatch_data == NULL)
        goto out;

    bbsub = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    status = apr_brigade_puts(bbsub, NULL, NULL, proppatch_data);
    if (status != APR_SUCCESS)
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, 0, status,
                             "Error postprocessing PROPPATCH part");

    b = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bbsub, b);

    rr = ap_sub_req_method_uri("PROPPATCH", r->uri, r, r->output_filters);
    if (!rr || rr->status != HTTP_OK) {
        return dav_new_error(r->pool,
                             rr ? rr->status : HTTP_INTERNAL_SERVER_ERROR,
                             0, 0, "PROPPATCH subrequest lookup failed");
    }

    f = ap_add_input_filter("DAV_MSWDV_IN", bbsub, rr, rr->connection);
    if (!f)
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0,
                             "DAV_MSWDV_IN filter not found");


    if ((ret = ap_run_sub_req(rr)) != OK) {
        char *errmsg = apr_psprintf(r->pool,
                                    "X-DAVMSEXT PROPPATCH status %d",
                                    ret);
        return dav_new_error(r->pool, rr->status, 0, 0, errmsg);
    }

    ap_remove_input_filter(f);

    ap_destroy_sub_req(rr);

out:
    return err;
}

DAV_DECLARE(apr_status_t) dav_mswdv_output(ap_filter_t *f,
                                           apr_bucket_brigade *bb)
{
    apr_bucket_brigade *bbsub = f->ctx;
    apr_bucket *b;

    b = APR_BRIGADE_FIRST(bb);
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        apr_bucket *nb;
        if (APR_BUCKET_IS_EOS(b))
            break;

        nb = APR_BUCKET_NEXT(b);
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(bbsub, b);
        b = nb;
    }

    return ap_pass_brigade(f->next, bb);
}

DAV_DECLARE(apr_status_t) dav_mswdv_input(ap_filter_t *f,
                                          apr_bucket_brigade *bb,
                                          ap_input_mode_t mode,
                                          apr_read_type_e block,
                                          apr_off_t readbytes)
{
    apr_bucket_brigade *bbsub = f->ctx;

    APR_BRIGADE_CONCAT(bb, bbsub);

    return APR_SUCCESS;
}

