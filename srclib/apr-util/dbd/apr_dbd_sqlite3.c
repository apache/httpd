/* Copyright 2000-2005 The Apache Software Foundation or its licensors, as
 * applicable.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "apu.h"

#if APU_HAVE_SQLITE3

#include <ctype.h>
#include <stdlib.h>

#include <sqlite3.h>

#include "apr_strings.h"
#include "apr_time.h"

#define MAX_RETRY_COUNT 15
#define MAX_RETRY_SLEEP 100000

typedef struct apr_dbd_t apr_dbd_t;
typedef struct apr_dbd_results_t apr_dbd_results_t;
typedef struct apr_dbd_column_t apr_dbd_column_t;
typedef struct apr_dbd_row_t apr_dbd_row_t;
typedef struct {
    int errnum;
    apr_dbd_t *handle;
} apr_dbd_transaction_t;

struct apr_dbd_t {
    sqlite3 *conn;
    apr_dbd_transaction_t *trans;
    apr_thread_mutex_t *mutex;
    apr_pool_t *pool;
};

struct apr_dbd_row_t {
    apr_dbd_results_t *res;
    apr_dbd_column_t **columns;
    apr_dbd_row_t *next_row;
    int columnCount;
    int rownum;
};

struct apr_dbd_column_t {
    char *name;
    char *value;
    int size;
    int type;
};

struct apr_dbd_results_t {
    int random;
    sqlite3 *handle;
    sqlite3_stmt *stmt;
    apr_dbd_row_t *next_row;
    size_t sz;
    int tuples;
};



typedef struct {
    const char *name;
    int prepared;
} apr_dbd_prepared_t;

#define dbd_sqlite3_is_success(x) (((x) == SQLITE_DONE ) \
		|| ((x) == SQLITE_OK ))

#define APR_DBD_INTERNAL
#include "apr_dbd.h"

static int dbd_sqlite3_select(apr_pool_t * pool, apr_dbd_t * sql, apr_dbd_results_t ** results, const char *query, int seek)
{
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int i, ret, retry_count;
    size_t num_tuples = 0;
    int increment = 0;
    apr_dbd_row_t *row = NULL;
    apr_dbd_row_t *lastrow = NULL;
    apr_dbd_column_t *column;

    char *hold = NULL;

    apr_thread_mutex_lock(sql->mutex);

    ret = sqlite3_prepare(sql->conn, query, strlen(query), &stmt, &tail);
    if (!dbd_sqlite3_is_success(ret)) {
        apr_thread_mutex_unlock(sql->mutex);
        return ret;
    } else {
        int column_count;
        column_count = sqlite3_column_count(stmt);
        if (!*results) {
            *results = apr_pcalloc(pool, sizeof(apr_dbd_results_t));
        }
        (*results)->stmt = stmt;
        (*results)->sz = column_count;
        (*results)->random = seek;
        (*results)->next_row = 0;
        (*results)->tuples = 0;
        do {
            ret = sqlite3_step((*results)->stmt);
            if (ret == SQLITE_BUSY) {
                if (retry_count++ > MAX_RETRY_COUNT) {
                    ret = SQLITE_ERROR;
                } else {
                    apr_thread_mutex_unlock(sql->mutex);
                    apr_sleep(MAX_RETRY_SLEEP);
                }
            } else if (ret == SQLITE_ROW) {
                int length;
                apr_dbd_column_t *col;
                row = apr_palloc(pool, sizeof(apr_dbd_row_t));
                row->res = *results;
                row->res->stmt = (*results)->stmt;
                increment = sizeof(apr_dbd_column_t *);
                length = increment * (*results)->sz;
                row->columns = apr_palloc(pool, length);
                row->columnCount = column_count;
                for (i = 0; i < (*results)->sz; i++) {
                    column = apr_palloc(pool, sizeof(apr_dbd_column_t));
                    row->columns[i] = column;
                    column->name = (char *) sqlite3_column_name((*results)->stmt, i);
                    column->size = sqlite3_column_bytes((*results)->stmt, i);
                    column->type = sqlite3_column_type((*results)->stmt, i);
                    switch (column->type) {

                    case SQLITE_FLOAT:
                        break;
                    case SQLITE_INTEGER:
                    case SQLITE_TEXT:
                        hold = NULL;
                        hold = (char *) sqlite3_column_text((*results)->stmt, i);
                        if (hold) {
                            column->value = apr_palloc(pool, column->size + 1);
                            strncpy(column->value, hold, column->size + 1);
                        }
                        break;
                    case SQLITE_BLOB:
                        break;
                    case SQLITE_NULL:
                        break;
                    }
                    col = row->columns[i];
                }
                row->rownum = num_tuples++;
                row->next_row = 0;
                (*results)->tuples = num_tuples;
                if ((*results)->next_row == 0) {
                    (*results)->next_row = row;
                }
                if (lastrow != 0) {
                    lastrow->next_row = row;
                }
                lastrow = row;
            } else if (ret == SQLITE_DONE) {
                ret = SQLITE_OK;
            }
        } while (ret == SQLITE_ROW || ret == SQLITE_BUSY);
    }
    ret = sqlite3_finalize(stmt);
    apr_thread_mutex_unlock(sql->mutex);
    return ret;
}

static int dbd_sqlite3_get_row(apr_pool_t * pool, apr_dbd_results_t * res, apr_dbd_row_t ** rowp, int rownum)
{
    int ret, retry_count, i = 0;
    apr_dbd_row_t *row;
    if (rownum == -1) {
        *rowp = res->next_row;
        if (*rowp == 0)
            return -1;
        res->next_row = (*rowp)->next_row;
        return 0;
    }
    if (rownum > res->tuples) {
        return -1;
    }
    rownum--;
    *rowp = res->next_row;
    for (; *rowp != 0; i++, *rowp = (*rowp)->next_row) {
        if (i == rownum) {
            return 0;
        }
    }

    return -1;

}

static const char *dbd_sqlite3_get_entry(const apr_dbd_row_t * row, int n)
{
    apr_dbd_column_t *column;
    const char *value;
    if ((n + 1) > row->columnCount) {
        return NULL;
    }
    column = row->columns[n];
    value = column->value;
    return value;
}

static const char *dbd_sqlite3_error(apr_dbd_t * sql, int n)
{
    return sqlite3_errmsg(sql->conn);
}

static int dbd_sqlite3_query(apr_dbd_t * sql, int *nrows, const char *query)
{
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    int ret, retry_count = 0, length = 0;
    apr_status_t res;
    apr_pool_t *pool;

    res = apr_pool_create(&pool, sql->pool);
    if (res != APR_SUCCESS) {
        return SQLITE_ERROR;
    }
    length = strlen(query);
    apr_thread_mutex_lock(sql->mutex);

    do {
        ret = sqlite3_prepare(sql->conn, query, length, &stmt, &tail);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(stmt);
            apr_thread_mutex_unlock(sql->mutex);
            return ret;
        }

        ret = sqlite3_step(stmt);
        *nrows = sqlite3_changes(sql->conn);
        sqlite3_finalize(stmt);
        length -= (tail - query);
        query = tail;
    } while (length > 0);

    if (dbd_sqlite3_is_success(ret)) {
        ret = 0;
    }
    apr_thread_mutex_unlock(sql->mutex);
    apr_pool_destroy(pool);
    return ret;
}

static const char *dbd_sqlite3_escape(apr_pool_t * pool, const char *arg, apr_dbd_t * sql)
{
    char *ret = sqlite3_mprintf(arg);
    apr_pool_cleanup_register(pool, ret, (void *) sqlite3_free, apr_pool_cleanup_null);
    return ret;
}

static int dbd_sqlite3_prepare(apr_pool_t * pool, apr_dbd_t * sql,
                               const char *query, const char *label, apr_dbd_prepared_t ** statement)
{
    return APR_ENOTIMPL;
}

static int dbd_sqlite3_pquery(apr_pool_t * pool, apr_dbd_t * sql,
                              int *nrows, apr_dbd_prepared_t * statement, int nargs, const char **values)
{
    return APR_ENOTIMPL;
}

static int dbd_sqlite3_pvquery(apr_pool_t * pool, apr_dbd_t * sql, int *nrows, apr_dbd_prepared_t * statement, ...)
{
    return APR_ENOTIMPL;
}

static int dbd_sqlite3_pselect(apr_pool_t * pool, apr_dbd_t * sql,
                               apr_dbd_results_t ** results,
                               apr_dbd_prepared_t * statement, int seek, int nargs, const char **values)
{
    return APR_ENOTIMPL;
}

static int dbd_sqlite3_pvselect(apr_pool_t * pool, apr_dbd_t * sql,
                                apr_dbd_results_t ** results, apr_dbd_prepared_t * statement, int seek, ...)
{
    return APR_ENOTIMPL;
}

static int dbd_sqlite3_start_transaction(apr_pool_t * pool, apr_dbd_t * handle, apr_dbd_transaction_t ** trans)
{
    int ret = 0;
    int nrows = 0;

    ret = dbd_sqlite3_query(handle, &nrows, "BEGIN TRANSACTION;");
    if (!*trans) {
        *trans = apr_pcalloc(pool, sizeof(apr_dbd_transaction_t));
        (*trans)->handle = handle;
        handle->trans = *trans;
    }

    return ret;
}

static int dbd_sqlite3_end_transaction(apr_dbd_transaction_t * trans)
{
    int ret = 0;
    int nrows = 0;

    if (trans) {
        ret = dbd_sqlite3_query(trans->handle, &nrows, "END TRANSACTION;");
        if (trans->errnum) {
            trans->errnum = 0;
            ret = dbd_sqlite3_query(trans->handle, &nrows, "ROLLBACK;");
        } else {
            ret = dbd_sqlite3_query(trans->handle, &nrows, "COMMIT;");
        }
        trans->handle->trans = NULL;
    }

    return ret;
}

static apr_dbd_t *dbd_sqlite3_open(apr_pool_t * pool, const char *params)
{
    apr_dbd_t *sql = NULL;
    sqlite3 *conn = NULL;
    apr_status_t res;
    int sqlres;
    if (!params)
        return NULL;
    sqlres = sqlite3_open(params, &conn);
    if (sqlres != SQLITE_OK) {
        sqlite3_close(conn);
        return NULL;
    }
    /* should we register rand or power functions to the sqlite VM? */
    sql = apr_pcalloc(pool, sizeof(*sql));
    sql->conn = conn;
    sql->pool = pool;
    /* Create a mutex */
    res = apr_thread_mutex_create(&sql->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    if (res != APR_SUCCESS) {
        return NULL;
    }

    return sql;
}

static apr_status_t dbd_sqlite3_close(apr_dbd_t * handle)
{
    sqlite3_close(handle->conn);
    apr_thread_mutex_destroy(handle->mutex);
    return APR_SUCCESS;
}

static apr_status_t dbd_sqlite3_check_conn(apr_pool_t * pool, apr_dbd_t * handle)
{
    return (handle->conn != NULL) ? APR_SUCCESS : APR_EGENERAL;
}

static int dbd_sqlite3_select_db(apr_pool_t * pool, apr_dbd_t * handle, const char *name)
{
    return APR_ENOTIMPL;
}

static void *dbd_sqlite3_native(apr_dbd_t * handle)
{
    return handle->conn;
}

static int dbd_sqlite3_num_cols(apr_dbd_results_t * res)
{
    return res->sz;
}

static int dbd_sqlite3_num_tuples(apr_dbd_results_t * res)
{
    return res->tuples;
}

APU_DECLARE_DATA const apr_dbd_driver_t apr_dbd_sqlite3_driver = {
    "sqlite3",
    NULL,
    dbd_sqlite3_native,
    dbd_sqlite3_open,
    dbd_sqlite3_check_conn,
    dbd_sqlite3_close,
    dbd_sqlite3_select_db,
    dbd_sqlite3_start_transaction,
    dbd_sqlite3_end_transaction,
    dbd_sqlite3_query,
    dbd_sqlite3_select,
    dbd_sqlite3_num_cols,
    dbd_sqlite3_num_tuples,
    dbd_sqlite3_get_row,
    dbd_sqlite3_get_entry,
    dbd_sqlite3_error,
    dbd_sqlite3_escape,
    dbd_sqlite3_prepare,
    dbd_sqlite3_pvquery,
    dbd_sqlite3_pvselect,
    dbd_sqlite3_pquery,
    dbd_sqlite3_pselect,
};
#endif
