#include <stdio.h>
#include <stdlib.h>

//APR Includes
#include <apr_general.h>
#include <apr_pools.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_thread_proc.h>

/* default listen port number */
#define DEF_LISTEN_PORT     8081

/* default socket backlog number. SOMAXCONN is a system default value */
#define DEF_SOCKET_BACKLOG  SOMAXCONN

/* default buffer size */
#define BUFSIZE         4096

static void* APR_THREAD_FUNC processConnection(apr_thread_t *thd, void *);

int listenServer(){
    //Setup a socket to listen on the address for incoming requests

    apr_socket_t *listenSocket;
    apr_pool_t *memPool;
    apr_status_t retStatus;
    apr_threadattr_t *thd_attr;
    apr_sockaddr_t *sa;

    apr_pool_create(&memPool, NULL);
    apr_threadattr_create(&thd_attr, memPool);

    retStatus = apr_sockaddr_info_get(&sa, NULL, APR_INET, DEF_LISTEN_PORT, 0, memPool);
    if (retStatus != APR_SUCCESS) {
        goto error;
    }

    retStatus = apr_socket_create(&listenSocket, sa->family, SOCK_DGRAM, APR_PROTO_UDP, memPool);
    if (retStatus != APR_SUCCESS) {
        printf("apr_socket_create failed\n");
        goto error;
    }

    apr_socket_opt_set(listenSocket, APR_SO_NONBLOCK, 0);
    apr_socket_timeout_set(listenSocket, -1);
    apr_socket_opt_set(listenSocket, APR_SO_REUSEADDR, 1);

    retStatus = apr_socket_bind(listenSocket, sa);
    if (retStatus != APR_SUCCESS) {
        printf("apr_socket_bind failed\n");
        goto error;
    }

    while (1) {

        apr_sockaddr_t *from;
        char buf[1024];
        char *ip_addr;
        apr_port_t fromport;
        apr_size_t len = sizeof(buf);

        // Create the from from some "random values".
        apr_sockaddr_info_get(&from, "127.1.2.3", APR_INET, 4242, 0, memPool);
        retStatus = apr_socket_recvfrom(from, listenSocket, 0, buf, &len);
        if (retStatus != APR_SUCCESS) {
            printf("apr_socket_recvfrom failed\n");
            goto error;
        }
        apr_sockaddr_ip_get(&ip_addr, from);
        fromport = from->port;
        printf("from: %d\n", fromport);
        printf("from: %s\n", ip_addr);
        printf("from: %.*s\n", len, buf);

        //Create the new thread
        apr_thread_t *thd_obj;
        apr_socket_t * ns;
        retStatus = apr_thread_create(&thd_obj, NULL, processConnection, ns, memPool);

        if(retStatus != APR_SUCCESS){
            printf("Error Creating new Thread\n");
        }

    }

    apr_pool_destroy(memPool);
    apr_terminate();
    return 0;

    error:
    {
        char errbuf[256];
        apr_strerror(retStatus, errbuf, sizeof(errbuf));
        printf("error: %d, %s\n", retStatus, errbuf);
    }

    apr_terminate();
    return -1;
}

static void* APR_THREAD_FUNC processConnection(apr_thread_t *thd, void* data){

    apr_socket_t * sock = (apr_socket_t*) data;

    while (1) {
        char buf[BUFSIZE];
        apr_size_t len = sizeof(buf) - 1;/* -1 for a null-terminated */

        apr_status_t rv = apr_socket_recv(sock, buf, &len);

        if (rv == APR_EOF || len == 0) {
            printf("Socket Closed\n");
            apr_socket_close(sock);
            break;
        }

        if(len > 0){
            printf("Read: %s\n", buf);
        }

        buf[len] = '\0';/* apr_socket_recv() doesn't return a null-terminated string */

    }

}

int main(int argc, const char * const argv[])
{
    apr_initialize();
    atexit(apr_terminate);
    listenServer();
}
