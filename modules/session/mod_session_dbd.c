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

#include "mod_session.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "http_log.h"
#include "util_cookies.h"
#include "apr_dbd.h"
#include "mod_dbd.h"
#include "mpm_common.h"

#define MOD_SESSION_DBD "mod_session_dbd"

module AP_MODULE_DECLARE_DATA session_dbd_module;

/**
 * Structure to carry the per-dir session config.
 */
typedef struct {
    const char *name;
    int name_set;
    const char *name_attrs;
    const char *name2;
    int name2_set;
    const char *name2_attrs;
    int peruser;
    int peruser_set;
    int remove;
    int remove_set;
    const char *selectlabel;
    const char *insertlabel;
    const char *updatelabel;
    const char *deletelabel;
} session_dbd_dir_conf;

/* optional function - look it up once in post_config */
static ap_dbd_t *(*session_dbd_acquire_fn) (request_rec *) = NULL;
static void (*session_dbd_prepare_fn) (server_rec *, const char *, const char *) = NULL;

/**
 * Initialise the database.
 *
 * If the mod_dbd module is missing, this method will return APR_EGENERAL.
 */
static apr_status_t dbd_init(request_rec *r, const char *query, ap_dbd_t **dbdp,
                             apr_dbd_prepared_t **statementp)
{
    ap_dbd_t *dbd;
    apr_dbd_prepared_t *statement;

    if (!session_dbd_prepare_fn || !session_dbd_acquire_fn) {
        session_dbd_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        session_dbd_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
        if (!session_dbd_prepare_fn || !session_dbd_acquire_fn) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01850)
                          "You must load mod_dbd to enable AuthDBD functions");
            return APR_EGENERAL;
        }
    }

    dbd = session_dbd_acquire_fn(r);
    if (!dbd) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01851)
                      "failed to acquire database connection");
        return APR_EGENERAL;
    }

    statement = apr_hash_get(dbd->prepared, query, APR_HASH_KEY_STRING);
    if (!statement) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01852)
                      "failed to find the prepared statement called '%s'", query);
        return APR_EGENERAL;
    }

    *dbdp = dbd;
    *statementp = statement;

    return APR_SUCCESS;
}

/**
 * Load the session by the key specified.
 */
static apr_status_t dbd_load(request_rec * r, const char *key, const char **val)
{

    apr_status_t rv;
    ap_dbd_t *dbd = NULL;
    apr_dbd_prepared_t *statement = NULL;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    apr_int64_t expiry = (apr_int64_t) apr_time_now();

    session_dbd_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_dbd_module);

    if (conf->selectlabel == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01853)
                      "no SessionDBDselectlabel has been specified");
        return APR_EGENERAL;
    }

    rv = dbd_init(r, conf->selectlabel, &dbd, &statement);
    if (rv) {
        return rv;
    }
    rv = apr_dbd_pvbselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                          0, key, &expiry, NULL);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01854)
                      "query execution error saving session '%s' "
                      "in database using query '%s': %s", key, conf->selectlabel,
                      apr_dbd_error(dbd->driver, dbd->handle, rv));
        return APR_EGENERAL;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01855)
                          "error retrieving results while saving '%s' "
                          "in database using query '%s': %s", key, conf->selectlabel,
                           apr_dbd_error(dbd->driver, dbd->handle, rv));
            return APR_EGENERAL;
        }
        if (*val == NULL) {
            *val = apr_dbd_get_entry(dbd->driver, row, 0);
        }
        /* we can't break out here or row won't get cleaned up */
    }

    return APR_SUCCESS;

}

/**
 * Load the session by firing off a dbd query.
 *
 * If the session is anonymous, the session key will be extracted from
 * the cookie specified. Failing that, the session key will be extracted
 * from the GET parameters.
 *
 * If the session is keyed by the username, the session will be extracted
 * by that.
 *
 * If no session is found, an empty session will be created.
 *
 * On success, this returns OK.
 */
static apr_status_t session_dbd_load(request_rec * r, session_rec ** z)
{

    session_dbd_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_dbd_module);

    apr_status_t ret = APR_SUCCESS;
    session_rec *zz = NULL;
    const char *name = NULL;
    const char *note = NULL;
    const char *val = NULL;
    const char *key = NULL;
    request_rec *m = r->main ? r->main : r;

    /* is our session in a cookie? */
    if (conf->name2_set) {
        name = conf->name2;
    }
    else if (conf->name_set) {
        name = conf->name;
    }
    else if (conf->peruser_set && r->user) {
        name = r->user;
    }
    else {
        return DECLINED;
    }

    /* first look in the notes */
    note = apr_pstrcat(r->pool, MOD_SESSION_DBD, name, NULL);
    zz = (session_rec *)apr_table_get(m->notes, note);
    if (zz) {
        *z = zz;
        return OK;
    }

    /* load anonymous sessions */
    if (conf->name_set || conf->name2_set) {

        /* load an RFC2109 or RFC2965 compliant cookie */
        ap_cookie_read(r, name, &key, conf->remove);
        if (key) {
            ret = dbd_load(r, key, &val);
            if (ret != APR_SUCCESS) {
                return ret;
            }
        }

    }

    /* load named session */
    else if (conf->peruser) {
        if (r->user) {
            ret = dbd_load(r, r->user, &val);
            if (ret != APR_SUCCESS) {
                return ret;
            }
        }
    }

    /* otherwise not for us */
    else {
        return DECLINED;
    }

    /* create a new session and return it */
    zz = (session_rec *) apr_pcalloc(r->pool, sizeof(session_rec));
    zz->pool = r->pool;
    zz->entries = apr_table_make(zz->pool, 10);
    if (key && val) {
        apr_uuid_t *uuid = apr_pcalloc(zz->pool, sizeof(apr_uuid_t));
        if (APR_SUCCESS == apr_uuid_parse(uuid, key)) {
            zz->uuid = uuid;
        }
    }
    zz->encoded = val;
    *z = zz;

    /* put the session in the notes so we don't have to parse it again */
    apr_table_setn(m->notes, note, (char *)zz);

    return OK;

}

/**
 * Save the session by the key specified.
 */
static apr_status_t dbd_save(request_rec * r, const char *oldkey,
        const char *newkey, const char *val, apr_int64_t expiry)
{

    apr_status_t rv;
    ap_dbd_t *dbd = NULL;
    apr_dbd_prepared_t *statement;
    int rows = 0;

    session_dbd_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_dbd_module);

    if (conf->updatelabel == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01856)
                      "no SessionDBDupdatelabel has been specified");
        return APR_EGENERAL;
    }

    rv = dbd_init(r, conf->updatelabel, &dbd, &statement);
    if (rv) {
        return rv;
    }

    if (oldkey) {
        rv = apr_dbd_pvbquery(dbd->driver, r->pool, dbd->handle, &rows,
                statement, val, &expiry, newkey, oldkey, NULL);
        if (rv) {
            ap_log_rerror(
                    APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01857) "query execution error updating session '%s' "
                    "using database query '%s': %s/%s", oldkey, newkey, conf->updatelabel, apr_dbd_error(dbd->driver, dbd->handle, rv));
            return APR_EGENERAL;
        }

        /*
         * if some rows were updated it means a session existed and was updated,
         * so we are done.
         */
        if (rows != 0) {
            return APR_SUCCESS;
        }
    }

    if (conf->insertlabel == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01858)
                      "no SessionDBDinsertlabel has been specified");
        return APR_EGENERAL;
    }

    rv = dbd_init(r, conf->insertlabel, &dbd, &statement);
    if (rv) {
        return rv;
    }
    rv = apr_dbd_pvbquery(dbd->driver, r->pool, dbd->handle, &rows, statement,
                          val, &expiry, newkey, NULL);
    if (rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01859)
                      "query execution error inserting session '%s' "
                      "in database with '%s': %s", newkey, conf->insertlabel,
                      apr_dbd_error(dbd->driver, dbd->handle, rv));
        return APR_EGENERAL;
    }

    /*
     * if some rows were inserted it means a session was inserted, so we are
     * done.
     */
    if (rows != 0) {
        return APR_SUCCESS;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01860)
                  "the session insert query did not cause any rows to be added "
                  "to the database for session '%s', session not inserted", newkey);

    return APR_EGENERAL;

}

/**
 * Remove the session by the key specified.
 */
static apr_status_t dbd_remove(request_rec * r, const char *key)
{

    apr_status_t rv;
    ap_dbd_t *dbd;
    apr_dbd_prepared_t *statement;
    int rows = 0;

    session_dbd_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_dbd_module);

    if (conf->deletelabel == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01862)
                      "no SessionDBDdeletelabel has been specified");
        return APR_EGENERAL;
    }

    rv = dbd_init(r, conf->deletelabel, &dbd, &statement);
    if (rv != APR_SUCCESS) {
        /* No need to do additional error logging here, it has already
           been done in dbd_init if needed */
        return rv;
    }

    rv = apr_dbd_pvbquery(dbd->driver, r->pool, dbd->handle, &rows, statement,
                          key, NULL);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01864)
                      "query execution error removing session '%s' "
                      "from database", key);
        return rv;
    }

    return APR_SUCCESS;

}

/**
 * Clean out expired sessions.
 *
 * TODO: We need to figure out a way to clean out expired sessions from the database.
 * The monitor hook doesn't help us that much, as we have no handle into the
 * server, and so we need to come up with a way to do this safely.
 */
static apr_status_t dbd_clean(apr_pool_t *p, server_rec *s)
{

    return APR_ENOTIMPL;

}

/**
 * Save the session by firing off a dbd query.
 *
 * If the session is anonymous, save the session and write a cookie
 * containing the uuid.
 *
 * If the session is keyed to the username, save the session using
 * the username as a key.
 *
 * On success, this method will return APR_SUCCESS.
 *
 * @param r The request pointer.
 * @param z A pointer to where the session will be written.
 */
static apr_status_t session_dbd_save(request_rec * r, session_rec * z)
{

    apr_status_t ret = APR_SUCCESS;
    session_dbd_dir_conf *conf = ap_get_module_config(r->per_dir_config,
                                                      &session_dbd_module);

    /* support anonymous sessions */
    if (conf->name_set || conf->name2_set) {
        char *oldkey = NULL, *newkey = NULL;

        /* don't cache pages with a session */
        apr_table_addn(r->headers_out, "Cache-Control", "no-cache");

        /* if the session is new or changed, make a new session ID */
        if (z->uuid) {
            oldkey = apr_pcalloc(r->pool, APR_UUID_FORMATTED_LENGTH + 1);
            apr_uuid_format(oldkey, z->uuid);
        }
        if (z->dirty || !oldkey) {
            z->uuid = apr_pcalloc(z->pool, sizeof(apr_uuid_t));
            apr_uuid_get(z->uuid);
            newkey = apr_pcalloc(r->pool, APR_UUID_FORMATTED_LENGTH + 1);
            apr_uuid_format(newkey, z->uuid);
        }
        else {
            newkey = oldkey;
        }

        /* save the session with the uuid as key */
        if (z->encoded && z->encoded[0]) {
            ret = dbd_save(r, oldkey, newkey, z->encoded, z->expiry);
        }
        else {
            ret = dbd_remove(r, oldkey);
        }
        if (ret != APR_SUCCESS) {
            return ret;
        }

        /* create RFC2109 compliant cookie */
        if (conf->name_set) {
            ap_cookie_write(r, conf->name, newkey, conf->name_attrs, z->maxage,
                            r->headers_out, r->err_headers_out, NULL);
        }

        /* create RFC2965 compliant cookie */
        if (conf->name2_set) {
            ap_cookie_write2(r, conf->name2, newkey, conf->name2_attrs, z->maxage,
                             r->headers_out, r->err_headers_out, NULL);
        }

        return OK;

    }

    /* save named session */
    else if (conf->peruser) {

        /* don't cache pages with a session */
        apr_table_addn(r->headers_out, "Cache-Control", "no-cache");

        if (r->user) {
            ret = dbd_save(r, r->user, r->user, z->encoded, z->expiry);
            if (ret != APR_SUCCESS) {
                return ret;
            }
            return OK;
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01865)
               "peruser sessions can only be saved if a user is logged in, "
                          "session not saved: %s", r->uri);
        }
    }

    return DECLINED;

}

/**
 * This function performs housekeeping on the database, deleting expired
 * sessions.
 */
static int session_dbd_monitor(apr_pool_t *p, server_rec *s)
{
    /* TODO handle housekeeping */
    dbd_clean(p, s);
    return OK;
}


static void *create_session_dbd_dir_config(apr_pool_t * p, char *dummy)
{
    session_dbd_dir_conf *new =
    (session_dbd_dir_conf *) apr_pcalloc(p, sizeof(session_dbd_dir_conf));

    new->remove = 1;

    new->selectlabel = "selectsession";
    new->insertlabel = "insertsession";
    new->updatelabel = "updatesession";
    new->deletelabel = "deletesession";

    return (void *) new;
}

static void *merge_session_dbd_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_dbd_dir_conf *new = (session_dbd_dir_conf *) apr_pcalloc(p, sizeof(session_dbd_dir_conf));
    session_dbd_dir_conf *add = (session_dbd_dir_conf *) addv;
    session_dbd_dir_conf *base = (session_dbd_dir_conf *) basev;

    new->name = (add->name_set == 0) ? base->name : add->name;
    new->name_attrs = (add->name_set == 0) ? base->name_attrs : add->name_attrs;
    new->name_set = add->name_set || base->name_set;
    new->name2 = (add->name2_set == 0) ? base->name2 : add->name2;
    new->name2_attrs = (add->name2_set == 0) ? base->name2_attrs : add->name2_attrs;
    new->name2_set = add->name2_set || base->name2_set;
    new->peruser = (add->peruser_set == 0) ? base->peruser : add->peruser;
    new->peruser_set = add->peruser_set || base->peruser_set;
    new->remove = (add->remove_set == 0) ? base->remove : add->remove;
    new->remove_set = add->remove_set || base->remove_set;
    new->selectlabel = (!add->selectlabel) ? base->selectlabel : add->selectlabel;
    new->updatelabel = (!add->updatelabel) ? base->updatelabel : add->updatelabel;
    new->insertlabel = (!add->insertlabel) ? base->insertlabel : add->insertlabel;
    new->deletelabel = (!add->deletelabel) ? base->deletelabel : add->deletelabel;

    return new;
}

/**
 * Sanity check a given string that it exists, is not empty,
 * and does not contain special characters.
 */
static const char *check_string(cmd_parms * cmd, const char *string)
{
    if (APR_SUCCESS != ap_cookie_check_string(string)) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive,
                           " cannot be empty, or contain '=', ';' or '&'.",
                           NULL);
    }
    return NULL;
}

static const char *
     set_dbd_peruser(cmd_parms * parms, void *dconf, int flag)
{
    session_dbd_dir_conf *conf = dconf;

    conf->peruser = flag;
    conf->peruser_set = 1;

    return NULL;
}

static const char *
     set_dbd_cookie_remove(cmd_parms * parms, void *dconf, int flag)
{
    session_dbd_dir_conf *conf = dconf;

    conf->remove = flag;
    conf->remove_set = 1;

    return NULL;
}

static const char *set_cookie_name(cmd_parms * cmd, void *config, const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_dbd_dir_conf *conf = (session_dbd_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name = cookie;
    conf->name_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name_attrs = last;
    return check_string(cmd, cookie);
}

static const char *set_cookie_name2(cmd_parms * cmd, void *config, const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_dbd_dir_conf *conf = (session_dbd_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name2 = cookie;
    conf->name2_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name2_attrs = last;
    return check_string(cmd, cookie);
}

static const command_rec session_dbd_cmds[] =
{
    AP_INIT_TAKE1("SessionDBDSelectLabel", ap_set_string_slot,
      (void *) APR_OFFSETOF(session_dbd_dir_conf, selectlabel), RSRC_CONF|OR_AUTHCFG,
                  "Query label used to select a new session"),
    AP_INIT_TAKE1("SessionDBDInsertLabel", ap_set_string_slot,
      (void *) APR_OFFSETOF(session_dbd_dir_conf, insertlabel), RSRC_CONF|OR_AUTHCFG,
                  "Query label used to insert a new session"),
    AP_INIT_TAKE1("SessionDBDUpdateLabel", ap_set_string_slot,
      (void *) APR_OFFSETOF(session_dbd_dir_conf, updatelabel), RSRC_CONF|OR_AUTHCFG,
                  "Query label used to update an existing session"),
    AP_INIT_TAKE1("SessionDBDDeleteLabel", ap_set_string_slot,
      (void *) APR_OFFSETOF(session_dbd_dir_conf, deletelabel), RSRC_CONF|OR_AUTHCFG,
                  "Query label used to delete an existing session"),
    AP_INIT_FLAG("SessionDBDPerUser", set_dbd_peruser, NULL, RSRC_CONF|OR_AUTHCFG,
                 "Save the session per user"),
    AP_INIT_FLAG("SessionDBDCookieRemove", set_dbd_cookie_remove, NULL, RSRC_CONF|OR_AUTHCFG,
                 "Remove the session cookie after session load. On by default."),
    AP_INIT_RAW_ARGS("SessionDBDCookieName", set_cookie_name, NULL, RSRC_CONF|OR_AUTHCFG,
                 "The name of the RFC2109 cookie carrying the session key"),
    AP_INIT_RAW_ARGS("SessionDBDCookieName2", set_cookie_name2, NULL, RSRC_CONF|OR_AUTHCFG,
                 "The name of the RFC2965 cookie carrying the session key"),
    {NULL}
};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_load(session_dbd_load, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_session_save(session_dbd_save, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_monitor(session_dbd_monitor, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(session_dbd) =
{
    STANDARD20_MODULE_STUFF,
    create_session_dbd_dir_config, /* dir config creater */
    merge_session_dbd_dir_config,  /* dir merger --- default is to
                                    * override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    session_dbd_cmds,              /* command apr_table_t */
    register_hooks                 /* register hooks */
};
