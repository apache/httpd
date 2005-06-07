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

#include "testutil.h"
#include "testsock.h"
#include "apr_thread_proc.h"
#include "apr_network_io.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_strings.h"

static void launch_child(abts_case *tc, apr_proc_t *proc, const char *arg1, apr_pool_t *p)
{
    apr_procattr_t *procattr;
    const char *args[3];
    apr_status_t rv;

    rv = apr_procattr_create(&procattr, p);
    APR_ASSERT_SUCCESS(tc, "Couldn't create procattr", rv);

    rv = apr_procattr_io_set(procattr, APR_NO_PIPE, APR_NO_PIPE,
            APR_NO_PIPE);
    APR_ASSERT_SUCCESS(tc, "Couldn't set io in procattr", rv);

    rv = apr_procattr_error_check_set(procattr, 1);
    APR_ASSERT_SUCCESS(tc, "Couldn't set error check in procattr", rv);

    args[0] = "sockchild" EXTENSION;
    args[1] = arg1;
    args[2] = NULL;
    rv = apr_proc_create(proc, "./sockchild" EXTENSION, args, NULL,
                         procattr, p);
    APR_ASSERT_SUCCESS(tc, "Couldn't launch program", rv);
}

static int wait_child(abts_case *tc, apr_proc_t *proc) 
{
    int exitcode;
    apr_exit_why_e why;

    ABTS_ASSERT(tc, "Error waiting for child process",
            apr_proc_wait(proc, &exitcode, &why, APR_WAIT) == APR_CHILD_DONE);

    ABTS_ASSERT(tc, "child terminated normally", why == APR_PROC_EXIT);
    return exitcode;
}

static void test_addr_info(abts_case *tc, void *data)
{
    apr_status_t rv;
    apr_sockaddr_t *sa;

    rv = apr_sockaddr_info_get(&sa, NULL, APR_UNSPEC, 80, 0, p);
    APR_ASSERT_SUCCESS(tc, "Problem generating sockaddr", rv);

    rv = apr_sockaddr_info_get(&sa, "127.0.0.1", APR_UNSPEC, 80, 0, p);
    APR_ASSERT_SUCCESS(tc, "Problem generating sockaddr", rv);
    ABTS_STR_EQUAL(tc, "127.0.0.1", sa->hostname);
}

static apr_socket_t *setup_socket(abts_case *tc)
{
    apr_status_t rv;
    apr_sockaddr_t *sa;
    apr_socket_t *sock;

    rv = apr_sockaddr_info_get(&sa, NULL, APR_INET, 8021, 0, p);
    APR_ASSERT_SUCCESS(tc, "Problem generating sockaddr", rv);

    rv = apr_socket_create(&sock, sa->family, SOCK_STREAM, APR_PROTO_TCP, p);
    APR_ASSERT_SUCCESS(tc, "Problem creating socket", rv);
    
    rv = apr_socket_bind(sock, sa);
    APR_ASSERT_SUCCESS(tc, "Problem binding to port", rv);
    if (rv) return NULL;
                
    rv = apr_socket_listen(sock, 5);
    APR_ASSERT_SUCCESS(tc, "Problem listening on socket", rv);

    return sock;
}

static void test_create_bind_listen(abts_case *tc, void *data)
{
    apr_status_t rv;
    apr_socket_t *sock = setup_socket(tc);
    
    if (!sock) return;
    
    rv = apr_socket_close(sock);
    APR_ASSERT_SUCCESS(tc, "Problem closing socket", rv);
}

static void test_send(abts_case *tc, void *data)
{
    apr_status_t rv;
    apr_socket_t *sock;
    apr_socket_t *sock2;
    apr_proc_t proc;
    int protocol;
    apr_size_t length;

    sock = setup_socket(tc);
    if (!sock) return;

    launch_child(tc, &proc, "read", p);
    
    rv = apr_socket_accept(&sock2, sock, p);
    APR_ASSERT_SUCCESS(tc, "Problem with receiving connection", rv);

    apr_socket_protocol_get(sock2, &protocol);
    ABTS_INT_EQUAL(tc, APR_PROTO_TCP, protocol);
    
    length = strlen(DATASTR);
    apr_socket_send(sock2, DATASTR, &length);

    /* Make sure that the client received the data we sent */
    ABTS_INT_EQUAL(tc, strlen(DATASTR), wait_child(tc, &proc));

    rv = apr_socket_close(sock2);
    APR_ASSERT_SUCCESS(tc, "Problem closing connected socket", rv);
    rv = apr_socket_close(sock);
    APR_ASSERT_SUCCESS(tc, "Problem closing socket", rv);
}

static void test_recv(abts_case *tc, void *data)
{
    apr_status_t rv;
    apr_socket_t *sock;
    apr_socket_t *sock2;
    apr_proc_t proc;
    int protocol;
    apr_size_t length = STRLEN;
    char datastr[STRLEN];
    
    sock = setup_socket(tc);
    if (!sock) return;

    launch_child(tc, &proc, "write", p);
    
    rv = apr_socket_accept(&sock2, sock, p);
    APR_ASSERT_SUCCESS(tc, "Problem with receiving connection", rv);

    apr_socket_protocol_get(sock2, &protocol);
    ABTS_INT_EQUAL(tc, APR_PROTO_TCP, protocol);
    
    memset(datastr, 0, STRLEN);
    apr_socket_recv(sock2, datastr, &length);

    /* Make sure that the server received the data we sent */
    ABTS_STR_EQUAL(tc, DATASTR, datastr);
    ABTS_INT_EQUAL(tc, strlen(datastr), wait_child(tc, &proc));

    rv = apr_socket_close(sock2);
    APR_ASSERT_SUCCESS(tc, "Problem closing connected socket", rv);
    rv = apr_socket_close(sock);
    APR_ASSERT_SUCCESS(tc, "Problem closing socket", rv);
}

static void test_timeout(abts_case *tc, void *data)
{
    apr_status_t rv;
    apr_socket_t *sock;
    apr_socket_t *sock2;
    apr_proc_t proc;
    int protocol;
    int exit;
    
    sock = setup_socket(tc);
    if (!sock) return;

    launch_child(tc, &proc, "read", p);
    
    rv = apr_socket_accept(&sock2, sock, p);
    APR_ASSERT_SUCCESS(tc, "Problem with receiving connection", rv);

    apr_socket_protocol_get(sock2, &protocol);
    ABTS_INT_EQUAL(tc, APR_PROTO_TCP, protocol);
    
    exit = wait_child(tc, &proc);    
    ABTS_INT_EQUAL(tc, SOCKET_TIMEOUT, exit);

    /* We didn't write any data, so make sure the child program returns
     * an error.
     */
    rv = apr_socket_close(sock2);
    APR_ASSERT_SUCCESS(tc, "Problem closing connected socket", rv);
    rv = apr_socket_close(sock);
    APR_ASSERT_SUCCESS(tc, "Problem closing socket", rv);
}

abts_suite *testsock(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test_addr_info, NULL);
    abts_run_test(suite, test_create_bind_listen, NULL);
    abts_run_test(suite, test_send, NULL);
    abts_run_test(suite, test_recv, NULL);
    abts_run_test(suite, test_timeout, NULL);

    return suite;
}

