/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2004 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
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

#include <stdio.h>
#include "httpd.h"
#include "http_conf_globals.h"

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
