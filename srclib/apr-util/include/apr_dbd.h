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

/* Overview of what this is and does:
 * http://www.apache.org/~niq/dbd.html
 */

#ifndef APR_DBD_H
#define APR_DBD_H

#ifdef __cplusplus
extern "C" {
#endif

/* These are opaque structs.  Instantiation is up to each backend */
#ifndef APR_DBD_INTERNAL
typedef struct apr_dbd_t apr_dbd_t;
typedef struct apr_dbd_transaction_t apr_dbd_transaction_t;
typedef struct apr_dbd_results_t apr_dbd_results_t;
typedef struct apr_dbd_row_t apr_dbd_row_t;
typedef struct apr_dbd_prepared_t apr_dbd_prepared_t;
#endif

typedef struct apr_dbd_driver_t {
    /** name */
    const char *name;

    /** init: allow driver to perform once-only initialisation.
     *  Called once only.  May be NULL
     */
    void (*init)(apr_pool_t *pool);

    /** native_handle: return the native database handle of the underlying db
     *
     * @param handle - apr_dbd handle
     * @return - native handle
     */
    void *(*native_handle)(apr_dbd_t *handle);

    /** open: obtain a database connection from the server rec.
     *  Must be explicitly closed when you're finished with it.
     *  WARNING: only use this when you need a connection with
     *  a lifetime other than a request
     *
     *  @param pool - a pool to use for error messages (if any).
     *  @param s - server rec managing the underlying connection/pool.
     *  @return database handle, or NULL on error.
     */
    apr_dbd_t *(*open)(apr_pool_t *pool, const char *params);

    /** check_conn: check status of a database connection
     *
     *  @param pool - a pool to use for error messages (if any).
     *  @param handle - the connection to check
     *  @return APR_SUCCESS or error
     */
    apr_status_t (*check_conn)(apr_pool_t *pool, apr_dbd_t *handle);

    /** close: close/release a connection obtained from open()
     *
     *  @param handle - the connection to release
     *  @return APR_SUCCESS or error
     */
    apr_status_t (*close)(apr_dbd_t *handle);

    /** set_dbname: select database name.  May be a no-op if not supported.
     *
     *  @param pool - working pool
     *  @param handle - the connection
     *  @param name - the database to select
     *  @return 0 for success or error code
     */
    int (*set_dbname)(apr_pool_t* pool, apr_dbd_t *handle, const char *name);

    /** transaction: start a transaction.  May be a no-op.
     *
     *  @param pool - a pool to use for error messages (if any).
     *  @param handle - the connection
     *  @param transaction - ptr to a transaction.  May be null on entry
     *  @return 0 for success or error code
     */
    int (*start_transaction)(apr_pool_t *pool, apr_dbd_t *handle,
                             apr_dbd_transaction_t **trans);

    /** end_transaction: end a transaction
     *  (commit on success, rollback on error).
     *  May be a no-op.
     *
     *  @param transaction - the transaction.
     *  @return 0 for success or error code
     */
    int (*end_transaction)(apr_dbd_transaction_t *trans);

    /** query: execute an SQL query that doesn't return a result set
     *
     *  @param handle - the connection
     *  @param nrows - number of rows affected.
     *  @param statement - the SQL statement to execute
     *  @return 0 for success or error code
     */
    int (*query)(apr_dbd_t *handle, int *nrows, const char *statement);

    /** select: execute an SQL query that returns a result set
     *
     *  @param pool - pool to allocate the result set
     *  @param handle - the connection
     *  @param res - pointer to result set pointer.  May point to NULL on entry
     *  @param statement - the SQL statement to execute
     *  @param random - 1 to support random access to results (seek any row);
     *                  0 to support only looping through results in order
     *                    (async access - faster)
     *  @return 0 for success or error code
     */
    int (*select)(apr_pool_t *pool, apr_dbd_t *handle, apr_dbd_results_t **res,
                  const char *statement, int random);

    /** num_cols: get the number of columns in a results set
     *
     *  @param res - result set.
     *  @return number of columns
     */
    int (*num_cols)(apr_dbd_results_t *res);

    /** num_tuples: get the number of rows in a results set
     *  of a synchronous select
     *
     *  @param res - result set.
     *  @return number of rows, or -1 if the results are asynchronous
     */
    int (*num_tuples)(apr_dbd_results_t *res);

    /** get_row: get a row from a result set
     *
     *  @param pool - pool to allocate the row
     *  @param res - result set pointer
     *  @param row - pointer to row pointer.  May point to NULL on entry
     *  @param rownum - row number, or -1 for "next row".  Ignored if random
     *                  access is not supported.
     *  @return 0 for success, -1 for rownum out of range or data finished
     */
    int (*get_row)(apr_pool_t *pool, apr_dbd_results_t *res,
                   apr_dbd_row_t **row, int rownum);
  
    /** get_entry: get an entry from a row
     *
     *  @param row - row pointer
     *  @param col - entry number
     *  @return value from the row, or NULL if col is out of bounds.
     */
    const char *(*get_entry)(const apr_dbd_row_t *row, int col);
  
    /** error: get current error message (if any)
     *
     *  @param handle - the connection
     *  @param errnum - error code from operation that returned an error
     *  @return the database current error message, or message for errnum
     *          (implementation-dependent whether errnum is ignored)
     */
    const char *(*error)(apr_dbd_t *handle, int errnum);
  
    /** escape: escape a string so it is safe for use in query/select
     *
     *  @param pool - pool to alloc the result from
     *  @param string - the string to escape
     *  @param handle - the connection
     *  @return the escaped, safe string
     */
    const char *(*escape)(apr_pool_t *pool, const char *string,
                          apr_dbd_t *handle);
  
    /** prepare: prepare a statement
     *
     *  @param pool - pool to alloc the result from
     *  @param handle - the connection
     *  @param query - the SQL query
     *  @param label - A label for the prepared statement.
     *                 use NULL for temporary prepared statements
     *                 (eg within a Request in httpd)
     *  @param statement - statement to prepare.  May point to null on entry.
     *  @return 0 for success or error code
     */
    int (*prepare)(apr_pool_t *pool, apr_dbd_t *handle, const char *query,
                   const char *label, apr_dbd_prepared_t **statement);

    /** pvquery: query using a prepared statement + args
     *
     *  @param pool - working pool
     *  @param handle - the connection
     *  @param nrows - number of rows affected.
     *  @param statement - the prepared statement to execute
     *  @param ... - args to prepared statement
     *  @return 0 for success or error code
     */
    int (*pvquery)(apr_pool_t *pool, apr_dbd_t *handle, int *nrows,
                   apr_dbd_prepared_t *statement, ...);

    /** pvselect: select using a prepared statement + args
     *
     *  @param pool - working pool
     *  @param handle - the connection
     *  @param res - pointer to query results.  May point to NULL on entry
     *  @param statement - the prepared statement to execute
     *  @param random - Whether to support random-access to results
     *  @param ... - args to prepared statement
     *  @return 0 for success or error code
     */
    int (*pvselect)(apr_pool_t *pool, apr_dbd_t *handle,
                    apr_dbd_results_t **res,
                    apr_dbd_prepared_t *statement, int random, ...);

    /** pquery: query using a prepared statement + args
     *
     *  @param pool - working pool
     *  @param handle - the connection
     *  @param nrows - number of rows affected.
     *  @param statement - the prepared statement to execute
     *  @param nargs - number of args to prepared statement
     *  @param args - args to prepared statement
     *  @return 0 for success or error code
     */
    int (*pquery)(apr_pool_t *pool, apr_dbd_t *handle, int *nrows,
                  apr_dbd_prepared_t *statement, int nargs, const char **args);

    /** pselect: select using a prepared statement + args
     *
     *  @param pool - working pool
     *  @param handle - the connection
     *  @param res - pointer to query results.  May point to NULL on entry
     *  @param statement - the prepared statement to execute
     *  @param random - Whether to support random-access to results
     *  @param nargs - number of args to prepared statement
     *  @param args - args to prepared statement
     *  @return 0 for success or error code
     */
    int (*pselect)(apr_pool_t *pool, apr_dbd_t *handle,
                   apr_dbd_results_t **res, apr_dbd_prepared_t *statement,
                   int random, int nargs, const char **args);


} apr_dbd_driver_t;

/** apr_dbd_init: perform once-only initialisation.  Call once only.
 *
 *  @param pool - pool to register any shutdown cleanups, etc
 */
APU_DECLARE(apr_status_t) apr_dbd_init(apr_pool_t *pool);

/** apr_dbd_get_driver: get the driver struct for a name
 *
 *  @param pool - (process) pool to register cleanup
 *  @param name - driver name
 *  @param driver - pointer to driver struct.
 *  @return APR_SUCCESS for success
 *  @return APR_ENOTIMPL for no driver (when DSO not enabled)
 *  @return APR_EDSOOPEN if DSO driver file can't be opened
 *  @return APR_ESYMNOTFOUND if the driver file doesn't contain a driver
 */
APU_DECLARE(apr_status_t) apr_dbd_get_driver(apr_pool_t *pool, const char *name,
                                             apr_dbd_driver_t **driver);

/** apr_dbd_open: open a connection to a backend
 *
 *  @param ptmp - working pool
 *  @param params - arguments to driver (implementation-dependent)
 *  @param handle - pointer to handle to return
 *  @param driver - driver struct.
 *  @return APR_SUCCESS for success
 *  @return APR_EGENERAL if driver exists but connection failed
 */
APU_DECLARE(apr_status_t) apr_dbd_open(apr_dbd_driver_t *driver,
                                       apr_pool_t *ptmp, const char *params,
                                       apr_dbd_t **handle);

#ifdef DOXYGEN
/** apr_dbd_close: close a connection to a backend.
 *  Only required for explicit close or
 *
 *  @param handle - handle to close
 *  @param driver - driver struct.
 *  @return APR_SUCCESS for success or error status
 */
APU_DECLARE(apr_status_t) apr_dbd_close(apr_dbd_driver_t *driver,
                                        apr_dbd_t *handle);
#else
#define apr_dbd_close(driver,handle) (driver)->close((handle))
#endif

/* apr-function-shaped versions of things */

#ifdef DOXYGEN
/** apr_dbd_name: get the name of the driver
 *
 *  @param driver - the driver
 *  @return - name
 */
APU_DECLARE(const char*) apr_dbd_name(apr_dbd_driver_t *driver);
#else
#define apr_dbd_name(driver) \
        (driver)->name
#endif

#ifdef DOXYGEN
/** apr_dbd_native_handle: get native database handle of the underlying db
 *
 *  @param driver - the driver
 *  @param handle - apr_dbd handle
 *  @return - native handle
 */
APU_DECLARE(void*) apr_dbd_native_handle(apr_dbd_driver_t *driver,
                                         apr_dbd_t *handle);
#else
#define apr_dbd_native_handle(driver,handler) \
        (driver)->native_handle(handler)
#endif

#ifdef DOXYGEN
/** check_conn: check status of a database connection
 *
 *  @param driver - the driver
 *  @param pool - working pool
 *  @param handle - the connection to check
 *  @return APR_SUCCESS or error
 */
APU_DECLARE(int) apr_dbd_check_conn(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                    apr_dbd_t *handle);
#else
#define apr_dbd_check_conn(driver,pool,handle) \
        (driver)->check_conn((pool),(handle))
#endif

#ifdef DOXYGEN
/** apr_dbd_set_dbname: select database name.  May be a no-op if not supported.
 *
 *  @param driver - the driver
 *  @param pool - working pool
 *  @param handle - the connection
 *  @param name - the database to select
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_set_dbname(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                    apr_dbd_t *handle, const char *name);
#else
#define apr_dbd_set_dbname(driver,pool,handle,name) \
        (driver)->set_dbname((pool),(handle),(name))
#endif

/** apr_dbd_transaction_start: start a transaction.  May be a no-op.
 *
 *  @param driver - the driver
 *  @param pool - a pool to use for error messages (if any).
 *  @param handle - the db connection
 *  @param transaction - ptr to a transaction.  May be null on entry
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_transaction_start(apr_dbd_driver_t *driver,
                                           apr_pool_t *pool,
                                           apr_dbd_t *handle,
                                           apr_dbd_transaction_t **trans);

/** apr_dbd_transaction_end: end a transaction
 *  (commit on success, rollback on error).
 *  May be a no-op.
 *
 *  @param driver - the driver
 *  @param handle - the db connection
 *  @param transaction - the transaction.
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_transaction_end(apr_dbd_driver_t *driver,
                                         apr_pool_t *pool,
                                         apr_dbd_transaction_t *trans);

#ifdef DOXYGEN
/** apr_dbd_query: execute an SQL query that doesn't return a result set
 *
 *  @param driver - the driver
 *  @param handle - the connection
 *  @param nrows - number of rows affected.
 *  @param statement - the SQL statement to execute
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_query(apr_dbd_driver_t *driver, apr_dbd_t *handle,
                               int *nrows, const char *statement);
#else
#define apr_dbd_query(driver,handle,nrows,statement) \
        (driver)->query((handle),(nrows),(statement))
#endif

#ifdef DOXYGEN
/** apr_dbd_select: execute an SQL query that returns a result set
 *
 *  @param driver - the driver
 *  @param pool - pool to allocate the result set
 *  @param handle - the connection
 *  @param res - pointer to result set pointer.  May point to NULL on entry
 *  @param statement - the SQL statement to execute
 *  @param random - 1 to support random access to results (seek any row);
 *                  0 to support only looping through results in order
 *                    (async access - faster)
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_select(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                apr_dbd_t *handle, apr_dbd_results_t *res,
                                const char *statement, int random);
#else
#define apr_dbd_select(driver,pool,handle,res,statement,random) \
        (driver)->select((pool),(handle),(res),(statement),(random))
#endif

#ifdef DOXYGEN
/** apr_dbd_num_cols: get the number of columns in a results set
 *
 *  @param driver - the driver
 *  @param res - result set.
 *  @return number of columns
 */
APU_DECLARE(int) apr_dbd_num_cols(apr_dbd_driver_t *driver,
                                  apr_dbd_results_t *res);
#else
#define apr_dbd_num_cols(driver,res) \
        (driver)->num_cols((res))
#endif

#ifdef DOXYGEN
/** apr_dbd_num_tuples: get the number of rows in a results set
 *  of a synchronous select
 *
 *  @param driver - the driver
 *  @param res - result set.
 *  @return number of rows, or -1 if the results are asynchronous
 */
APU_DECLARE(int) apr_dbd_num_tuples(apr_dbd_driver_t *driver,
                                    apr_dbd_results_t *res);
#else
#define apr_dbd_num_tuples(driver,res) \
        (driver)->num_tuples((res))
#endif

#ifdef DOXYGEN
/** apr_dbd_get_row: get a row from a result set
 *
 *  @param driver - the driver
 *  @param pool - pool to allocate the row
 *  @param res - result set pointer
 *  @param row - pointer to row pointer.  May point to NULL on entry
 *  @param rownum - row number, or -1 for "next row".  Ignored if random
 *                  access is not supported.
 *  @return 0 for success, -1 for rownum out of range or data finished
 */
APU_DECLARE(int) apr_dbd_get_row(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                 apr_dbd_results_t *res, apr_dbd_row_t **row,
                                 int rownum);
#else
#define apr_dbd_get_row(driver,pool,res,row,rownum) \
        (driver)->get_row((pool),(res),(row),(rownum))
#endif

#ifdef DOXYGEN
/** apr_dbd_get_entry: get an entry from a row
 *
 *  @param driver - the driver
 *  @param row - row pointer
 *  @param col - entry number
 *  @return value from the row, or NULL if col is out of bounds.
 */
APU_DECLARE(const char*) apr_dbd_get_entry(apr_dbd_driver_t *driver,
                                           apr_dbd_row_t *row, int col);
#else
#define apr_dbd_get_entry(driver,row,col) \
        (driver)->get_entry((row),(col))
#endif

#ifdef DOXYGEN
/** apr_dbd_error: get current error message (if any)
 *
 *  @param driver - the driver
 *  @param handle - the connection
 *  @param errnum - error code from operation that returned an error
 *  @return the database current error message, or message for errnum
 *          (implementation-dependent whether errnum is ignored)
 */
APU_DECLARE(const char*) apr_dbd_error(apr_dbd_driver_t *driver,
                                       apr_dbd_t *handle, int errnum);
#else
#define apr_dbd_error(driver,handle,errnum) \
        (driver)->error((handle),(errnum))
#endif

#ifdef DOXYGEN
/** apr_dbd_escape: escape a string so it is safe for use in query/select
 *
 *  @param driver - the driver
 *  @param pool - pool to alloc the result from
 *  @param string - the string to escape
 *  @param handle - the connection
 *  @return the escaped, safe string
 */
APU_DECLARE(const char*) apr_dbd_escape(apr_dbd_driver_t *driver,
                                        apr_pool_t *pool, const char *string,
                                        apr_dbd_t *handle);
#else
#define apr_dbd_escape(driver,pool,string,handle) \
        (driver)->escape((pool),(string),(handle))
#endif

#ifdef DOXYGEN
/** apr_dbd_prepare: prepare a statement
 *
 *  @param driver - the driver
 *  @param pool - pool to alloc the result from
 *  @param handle - the connection
 *  @param query - the SQL query
 *  @param label - A label for the prepared statement.
 *                 use NULL for temporary prepared statements
 *                 (eg within a Request in httpd)
 *  @param statement - statement to prepare.  May point to null on entry.
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_prepare(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                 apr_dbd_t *handle, const char *query,
                                 const char *label,
                                 apr_dbd_prepared_t **statement);
#else
#define apr_dbd_prepare(driver,pool,handle,query,label,statement) \
        (driver)->prepare((pool),(handle),(query),(label),(statement))
#endif



/* need macros that do varargs to deal with pvquery and pvselect :-) */

#ifdef DOXYGEN
/** apr_dbd_pquery: query using a prepared statement + args
 *
 *  @param driver - the driver
 *  @param pool - working pool
 *  @param handle - the connection
 *  @param nrows - number of rows affected.
 *  @param statement - the prepared statement to execute
 *  @param nargs - number of args to prepared statement
 *  @param args - args to prepared statement
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_pquery(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                apr_dbd_t *handle, int *nrows,
                                apr_dbd_prepared_t *statement, int nargs,
                                const char **args);
#else
#define apr_dbd_pquery(driver,pool,handle,nrows,statement,nargs,args) \
        (driver)->pquery((pool),(handle),(nrows),(statement), \
                         (nargs),(args))
#endif

#ifdef DOXYGEN
/** apr_dbd_pselect: select using a prepared statement + args
 *
 *  @param driver - the driver
 *  @param pool - working pool
 *  @param handle - the connection
 *  @param res - pointer to query results.  May point to NULL on entry
 *  @param statement - the prepared statement to execute
 *  @param random - Whether to support random-access to results
 *  @param nargs - number of args to prepared statement
 *  @param args - args to prepared statement
 *  @return 0 for success or error code
 */
APU_DECLARE(int) apr_dbd_pselect(apr_dbd_driver_t *driver, apr_pool_t *pool,
                                 apr_dbd_t *handle, apr_dbd_results_t **res,
                                 apr_dbd_prepared_t *statement, int random,
                                 int nargs, const char **args);
#else
#define apr_dbd_pselect(driver,pool,handle,res,statement,random,nargs,args) \
        (driver)->pselect((pool),(handle),(res),(statement), \
                          (random),(nargs),(args))
#endif

#ifdef __cplusplus
}
#endif

#endif
