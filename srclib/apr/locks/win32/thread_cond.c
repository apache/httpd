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

#include "apr.h"
#include "apr_private.h"
#include "apr_general.h"
#include "apr_strings.h"
#include "win32/apr_arch_thread_mutex.h"
#include "win32/apr_arch_thread_cond.h"
#include "apr_portable.h"

static apr_status_t thread_cond_cleanup(void *data)
{
    apr_thread_cond_t *cond = data;
    CloseHandle(cond->mutex);
    CloseHandle(cond->event);
    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_thread_cond_create(apr_thread_cond_t **cond,
                                                 apr_pool_t *pool)
{
    *cond = apr_palloc(pool, sizeof(**cond));
    (*cond)->pool = pool;
    (*cond)->event = CreateEvent(NULL, TRUE, FALSE, NULL);
    (*cond)->mutex = CreateMutex(NULL, FALSE, NULL);
    (*cond)->signal_all = 0;
    (*cond)->num_waiting = 0;
    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_thread_cond_wait(apr_thread_cond_t *cond,
                                               apr_thread_mutex_t *mutex)
{
    DWORD res;

    while (1) {
        res = WaitForSingleObject(cond->mutex, INFINITE);
        if (res != WAIT_OBJECT_0) {
            return apr_get_os_error();
        }
        cond->num_waiting++;
        ReleaseMutex(cond->mutex);

        apr_thread_mutex_unlock(mutex);
        res = WaitForSingleObject(cond->event, INFINITE);
        cond->num_waiting--;
        if (res != WAIT_OBJECT_0) {
            apr_status_t rv = apr_get_os_error();
            ReleaseMutex(cond->mutex);
            return rv;
        }
        if (cond->signal_all) {
            if (cond->num_waiting == 0) {
                ResetEvent(cond->event);
            }
            break;
        }
        if (cond->signalled) {
            cond->signalled = 0;
            ResetEvent(cond->event);
            break;
        }
        ReleaseMutex(cond->mutex);
    }
    apr_thread_mutex_lock(mutex);
    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_thread_cond_timedwait(apr_thread_cond_t *cond,
                                                    apr_thread_mutex_t *mutex,
                                                    apr_interval_time_t timeout)
{
    DWORD res;
    DWORD timeout_ms = (DWORD) apr_time_as_msec(timeout);

    while (1) {
        res = WaitForSingleObject(cond->mutex, timeout_ms);
        if (res != WAIT_OBJECT_0) {
            if (res == WAIT_TIMEOUT) {
                return APR_TIMEUP;
            }
            return apr_get_os_error();
        }
        cond->num_waiting++;
        ReleaseMutex(cond->mutex);

        apr_thread_mutex_unlock(mutex);
        res = WaitForSingleObject(cond->event, timeout_ms);
        cond->num_waiting--;
        if (res != WAIT_OBJECT_0) {
            apr_status_t rv = apr_get_os_error();
            ReleaseMutex(cond->mutex);
            apr_thread_mutex_lock(mutex);
            if (res == WAIT_TIMEOUT) {
                return APR_TIMEUP;
            }
            return apr_get_os_error();
        }
        if (cond->signal_all) {
            if (cond->num_waiting == 0) {
                ResetEvent(cond->event);
            }
            break;
        }
        if (cond->signalled) {
            cond->signalled = 0;
            ResetEvent(cond->event);
            break;
        }
        ReleaseMutex(cond->mutex);
    }
    apr_thread_mutex_lock(mutex);
    return APR_SUCCESS;
}

APR_DECLARE(apr_status_t) apr_thread_cond_signal(apr_thread_cond_t *cond)
{
    apr_status_t rv = APR_SUCCESS;
    DWORD res;

    res = WaitForSingleObject(cond->mutex, INFINITE);
    if (res != WAIT_OBJECT_0) {
        return apr_get_os_error();
    }
    cond->signalled = 1;
    res = SetEvent(cond->event);
    if (res == 0) {
        rv = apr_get_os_error();
    }
    ReleaseMutex(cond->mutex);
    return rv;
}

APR_DECLARE(apr_status_t) apr_thread_cond_broadcast(apr_thread_cond_t *cond)
{
    apr_status_t rv = APR_SUCCESS;
    DWORD res;

    res = WaitForSingleObject(cond->mutex, INFINITE);
    if (res != WAIT_OBJECT_0) {
        return apr_get_os_error();
    }
    cond->signalled = 1;
    cond->signal_all = 1;
    res = SetEvent(cond->event);
    if (res == 0) {
        rv = apr_get_os_error();
    }
    ReleaseMutex(cond->mutex);
    return rv;
}

APR_DECLARE(apr_status_t) apr_thread_cond_destroy(apr_thread_cond_t *cond)
{
    return apr_pool_cleanup_run(cond->pool, cond, thread_cond_cleanup);
}

APR_POOL_IMPLEMENT_ACCESSOR(thread_cond)

