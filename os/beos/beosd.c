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

#include <unistd.h>
#include "httpd.h"
#include "http_config.h"
#include "http_main.h"
#include "http_log.h"
#include "beosd.h"
#include "mpm_common.h"

beosd_config_rec beosd_config;

/* Set group privileges.
 *
 * Note that until we get the multi-user situation sorted on beos,
 * this is just a no-op to allow common configuration files!
 */

#if B_BEOS_VERSION < 0x0460
static int set_group_privs(void)
{
    /* no-op */
    return 0;
}
#endif


int beosd_setup_child(void)
{
    /* TODO: revisit the whole issue of users/groups for BeOS as
     * R5 and below doesn't really have much concept of them.
     */

    return 0;
}


AP_DECLARE(const char *) beosd_set_user(cmd_parms *cmd,
                                        void *dummy, const char *arg)
{
    /* no-op */
    return NULL;
}

AP_DECLARE(const char *) beosd_set_group(cmd_parms *cmd,
                                         void *dummy, const char *arg)
{
    /* no-op */
    return NULL;
}

void beosd_pre_config(void)
{
    /* Until the multi-user situation on BeOS is fixed,
       simply have a no-op here to allow for common conf files
     */
}

AP_DECLARE(apr_status_t) beosd_accept(void **accepted, ap_listen_rec *lr,
                                      apr_pool_t *ptrans)
{
    apr_socket_t *csd;
    apr_status_t status;
    int sockdes;

    status = apr_socket_accept(&csd, lr->sd, ptrans);
    if (status == APR_SUCCESS) {
        *accepted = csd;
        apr_os_sock_get(&sockdes, csd);
        if (sockdes >= FD_SETSIZE) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, NULL,
                         "new file descriptor %d is too large; you probably need "
                         "to rebuild Apache with a larger FD_SETSIZE "
                         "(currently %d)",
                         sockdes, FD_SETSIZE);
            apr_socket_close(csd);
            return APR_EINTR;
        }
        return status;
    }

    if (APR_STATUS_IS_EINTR(status)) {
        return status;
    }
    /* Our old behaviour here was to continue after accept()
     * errors.  But this leads us into lots of troubles
     * because most of the errors are quite fatal.  For
     * example, EMFILE can be caused by slow descriptor
     * leaks (say in a 3rd party module, or libc).  It's
     * foolish for us to continue after an EMFILE.  We also
     * seem to tickle kernel bugs on some platforms which
     * lead to never-ending loops here.  So it seems best
     * to just exit in most cases.
     */
    switch (status) {
#ifdef EPROTO
        /* EPROTO on certain older kernels really means
         * ECONNABORTED, so we need to ignore it for them.
         * See discussion in new-httpd archives nh.9701
         * search for EPROTO.
         *
         * Also see nh.9603, search for EPROTO:
         * There is potentially a bug in Solaris 2.x x<6,
         * and other boxes that implement tcp sockets in
         * userland (i.e. on top of STREAMS).  On these
         * systems, EPROTO can actually result in a fatal
         * loop.  See PR#981 for example.  It's hard to
         * handle both uses of EPROTO.
         */
        case EPROTO:
#endif
#ifdef ECONNABORTED
        case ECONNABORTED:
#endif
#ifdef ETIMEDOUT
        case ETIMEDOUT:
#endif
#ifdef EHOSTUNREACH
        case EHOSTUNREACH:
#endif
#ifdef ENETUNREACH
        case ENETUNREACH:
#endif
            break;
#ifdef ENETDOWN
        case ENETDOWN:
            /*
             * When the network layer has been shut down, there
             * is not much use in simply exiting: the parent
             * would simply re-create us (and we'd fail again).
             * Use the CHILDFATAL code to tear the server down.
             * @@@ Martin's idea for possible improvement:
             * A different approach would be to define
             * a new APEXIT_NETDOWN exit code, the reception
             * of which would make the parent shutdown all
             * children, then idle-loop until it detected that
             * the network is up again, and restart the children.
             * Ben Hyde noted that temporary ENETDOWN situations
             * occur in mobile IP.
             */
            ap_log_error(APLOG_MARK, APLOG_EMERG, status, ap_server_conf,
                         "apr_socket_accept: giving up.");
            return APR_EGENERAL;
#endif /*ENETDOWN*/

        default:
            ap_log_error(APLOG_MARK, APLOG_ERR, status, ap_server_conf,
                         "apr_socket_accept: (client socket)");
            return APR_EGENERAL;
    }
    return status;
}
