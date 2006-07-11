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

/*
 * Given one or more group identifers on the command line (e.g.,
 * "httpd" or "#-1"), figure out whether they'll be valid for
 * the server to use at run-time.
 *
 * If a groupname isn't found, or we can't setgid() to it, return
 * -1.  If all groups are valid, return 0.
 *
 * This may need to be run as the superuser for the setgid() to
 * succeed; running it as any other user may result in a false
 * negative.
 */

#include "ap_config.h"
#if APR_HAVE_STDIO_H
#include <stdio.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

int main(int argc, char *argv[])
{
    int i;
    int result;
    gid_t gid;
    struct group *grent;
    struct group fake_grent;

    /*
     * Assume success. :-)
     */
    result = 0;
    for (i = 1; i < argc; ++i) {
        char *arg;
        arg = argv[i];

        /*
         * If it's from a 'Group #-1' statement, get the numeric value
         * and skip the group lookup stuff.
         */
        if (*arg == '#') {
            gid = atoi(&arg[1]);
            fake_grent.gr_gid = gid;
            grent = &fake_grent;
        }
        else {
            grent = getgrnam(arg);
        }

        /*
         * A NULL return means no such group was found, so we're done
         * with this one.
         */
        if (grent == NULL) {
            fprintf(stderr, "%s: group '%s' not found\n", argv[0], arg);
            result = -1;
        }
        else {
            int check;

            /*
             * See if we can switch to the numeric GID we have. If so,
             * all well and good; if not, well..
             */
            gid = grent->gr_gid;
            check = setgid(gid);
            if (check != 0) {
                fprintf(stderr, "%s: invalid group '%s'\n", argv[0], arg);
                perror(argv[0]);
                result = -1;
            }
        }
    }
    /*
     * Worst-case return value.
     */
    return result;
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "bsd"
 * End:
 */
