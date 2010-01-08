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
 * ap_slack.c: File descriptor preallocation
 * 
 * 3/21/93 Rob McCool
 * 1995-96 Many changes by the Apache Group
 * 
 */

#include "httpd.h"
#include "http_log.h"

#ifndef NO_SLACK
int ap_slack(int fd, int line)
{
#if !defined(F_DUPFD)
    return fd;
#else
    static int low_warned;
    int new_fd;

#ifdef HIGH_SLACK_LINE
    if (line == AP_SLACK_HIGH && fd < HIGH_SLACK_LINE) {
	new_fd = fcntl(fd, F_DUPFD, HIGH_SLACK_LINE);
	if (new_fd != -1) {
	    close(fd);
	    return new_fd;
	}
    }
#endif
    /* otherwise just assume line == AP_SLACK_LOW */
    if (fd >= LOW_SLACK_LINE) {
	return fd;
    }
    new_fd = fcntl(fd, F_DUPFD, LOW_SLACK_LINE);
    if (new_fd == -1) {
	if (!low_warned) {
	    /* Give them a warning here, because we really can't predict
	     * how libraries and such are going to fail.  If we can't
	     * do this F_DUPFD there's a good chance that apache has too
	     * few descriptors available to it.  Note we don't warn on
	     * the high line, because if it fails we'll eventually try
	     * the low line...
	     */
	    ap_log_error(APLOG_MARK, APLOG_WARNING, NULL,
		        "unable to open a file descriptor above %u, "
			"you may need to increase the number of descriptors",
			LOW_SLACK_LINE);
	    low_warned = 1;
	}
	return fd;
    }
    close(fd);
    return new_fd;
#endif
}
#else
/* need at least one function in the file for some linkers */
void ap_slack_is_not_here(void) {}
#endif /* NO_SLACK */
