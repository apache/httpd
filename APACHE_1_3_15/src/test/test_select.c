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
