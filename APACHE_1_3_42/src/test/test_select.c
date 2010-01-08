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

/* This is just a quick test program to see how long a wait is
 * produced by a select loop with an exponential backoff.
 *
 *   gcc -g -O2 -o test_select test_select.c
 *   test_select
 *
 * Roy Fielding, 1996
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

int main (void)
{
    int srv;
    long waittime = 4096;
    struct timeval tv;

    printf("Start\n");
    while ((waittime > 0) && (waittime < 3000000)) {
        printf("%d\n", waittime);
        tv.tv_sec  = waittime/1000000;
        tv.tv_usec = waittime%1000000;
        waittime <<= 1;
        srv = select(0, NULL, NULL, NULL, &tv);
    }
    printf("End\n");
    exit(0);
}
