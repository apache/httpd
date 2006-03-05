/* Copyright 2006 The Apache Software Foundation or its licensors, as
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

#include <apr.h>
#include <apr_pools.h>
#include <apr_network_io.h>
#include <apr_thread_proc.h>
#include <apr_getopt.h>
#include <apr_portable.h>

#if APR_HAVE_STDLIB_H
#include <stdlib.h> /* For EXIT_SUCCESS, EXIT_FAILURE */
#endif

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* For execl */
#endif

static void usage()
{
    fprintf(stderr,
            "usage: fcgistarter -c <command> -p <port> [-i <interface>]\n"
            "\n"
            "If an interface is not specified, any available will be used.\n");

    exit(EXIT_FAILURE);
}

static void exit_error(apr_status_t rv, const char *func)
{
    char buffer[1024];

    fprintf(stderr,
            "%s: %s\n",
            func,
            apr_strerror(rv, buffer, sizeof(buffer)));

    exit(EXIT_FAILURE);
}

int main(int argc, const char *argv[])
{
    apr_file_t *infd, *skwrapper;
    apr_sockaddr_t *skaddr;
    apr_procattr_t *pattr;
    apr_getopt_t *gopt;
    apr_socket_t *skt;
    apr_pool_t *pool;
    apr_status_t rv;
    apr_proc_t proc;


    /* Command line arguments */
    const char *interface = NULL;
    const char *command = NULL;
    int port = 0;

    apr_initialize();

    atexit(apr_terminate);

    apr_pool_create(&pool, NULL);

    rv = apr_getopt_init(&gopt, pool, argc, argv);
    if (rv) {
        return EXIT_FAILURE;
    }

    for (;;) {
        const char *arg;
        char opt;

        rv = apr_getopt(gopt, "c:p:i:", &opt, &arg);
        if (APR_STATUS_IS_EOF(rv)) {
            break;
        } else if (rv) {
            usage();
        } else {
            switch (opt) {
            case 'c':
                command = arg;
                break;

            case 'p':
                port = atoi(arg);
                if (! port) {
                    usage();
                }
                break;

            case 'i':
                interface = arg;
                break;

            default:
                break;
            }
        }
    }

    if (! command || ! port) {
        usage();
    }

    rv = apr_socket_create(&skt, APR_INET, SOCK_STREAM, APR_PROTO_TCP, pool);
    if (rv) {
        exit_error(rv, "apr_socket_create");
    }

    rv = apr_sockaddr_info_get(&skaddr, interface, APR_UNSPEC, port, 0, pool);
    if (rv) {
        exit_error(rv, "apr_sockaddr_info_get");
    }

    rv = apr_socket_bind(skt, skaddr);
    if (rv) {
        exit_error(rv, "apr_socket_bind");
    }

    rv = apr_socket_listen(skt, 1024);
    if (rv) {
        exit_error(rv, "apr_socket_listen");
    }

    rv = apr_proc_fork(&proc, pool);
    if (rv == APR_INCHILD) {
        apr_os_file_t oft = 0;
        apr_os_sock_t oskt;

        rv = apr_proc_detach(APR_PROC_DETACH_DAEMONIZE);
        if (rv) {
            exit_error(rv, "apr_proc_detach");
        }

#if defined(WIN32) || defined(OS2) || defined(NETWARE)
#error "Please implement me."
#else
        /* Ok, so we need a file that has file descriptor 0 (which
         * FastCGI wants), but points to our socket.  This isn't really
         * possible in APR, so we cheat a bit.  I have no idea how to
         * do this on a non-unix platform, so for now this is platform
         * specific.  Ick.
         *
         * Note that this has to happen post-detach, otherwise fd 0
         * gets closed during apr_proc_detach and it's all for nothing.
         *
         * Unfortunately, doing this post detach means we have no way
         * to let anyone know if there's a problem at this point :( */

        rv = apr_os_file_put(&infd, &oft, APR_READ | APR_WRITE, pool);
        if (rv) {
            exit(EXIT_FAILURE);
        }

        rv = apr_os_sock_get(&oskt, skt);
        if (rv) {
            exit(EXIT_FAILURE);
        }

        rv = apr_os_file_put(&skwrapper, &oskt, APR_READ | APR_WRITE,
                             pool);
        if (rv) {
            exit(EXIT_FAILURE);
        }

        rv = apr_file_dup2(infd, skwrapper, pool);
        if (rv) {
            exit(EXIT_FAILURE);
        }

        /* XXX Can't use apr_proc_create because there's no way to get
         *     infd into the procattr without going through another dup2,
         *     which means by the time it gets to the fastcgi process it
         *     is no longer fd 0, so it doesn't work.  Sigh. */

        execl(command, NULL);
#endif
    } else if (rv == APR_INPARENT) {
        apr_socket_close(skt);
    } else {
       exit_error(rv, "apr_proc_fork");
    }

    return EXIT_SUCCESS;
}
