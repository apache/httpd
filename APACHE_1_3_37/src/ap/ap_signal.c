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

#include "httpd.h"

#ifndef NO_USE_SIGACTION
/*
 * Replace standard signal() with the more reliable sigaction equivalent
 * from W. Richard Stevens' "Advanced Programming in the UNIX Environment"
 * (the version that does not automatically restart system calls).
 */
Sigfunc *signal(int signo, Sigfunc * func)
{
    struct sigaction act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef  SA_INTERRUPT		/* SunOS */
    act.sa_flags |= SA_INTERRUPT;
#endif
    if (sigaction(signo, &act, &oact) < 0)
	return SIG_ERR;
    return oact.sa_handler;
}
#else
/* need some function in this file, otherwise the linker on NeXT bitches */
void ap_signal_is_not_here(void) {}
#endif
