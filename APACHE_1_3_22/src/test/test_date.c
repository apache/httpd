/* This program tests the parseHTTPdate routine in ../main/util_date.c.
 *
 * It is only semiautomated in that I would run it, modify the code to
 * use a different algorithm or seed, recompile and run again, etc.
 * Obviously it should use an argument for that, but I never got around
 * to changing the implementation.
 * 
 *     gcc -g -O2 -I../main -o test_date ../main/util_date.o test_date.c
 *     test_date | egrep '^No '
 * 
 * Roy Fielding, 1996
 */
#define API_EXPORT(x) x

#include <stdio.h>
#include <stdlib.h>
#include "util_date.h"

static const long year2secs[] = {
             0L,    /* 1970 */
      31536000L,    /* 1971 */
      63072000L,    /* 1972 */
      94694400L,    /* 1973 */
     126230400L,    /* 1974 */
     157766400L,    /* 1975 */
     189302400L,    /* 1976 */
     220924800L,    /* 1977 */
     252460800L,    /* 1978 */
     283996800L,    /* 1979 */
     315532800L,    /* 1980 */
     347155200L,    /* 1981 */
     378691200L,    /* 1982 */
     410227200L,    /* 1983 */
     441763200L,    /* 1984 */
     473385600L,    /* 1985 */
     504921600L,    /* 1986 */
     536457600L,    /* 1987 */
     567993600L,    /* 1988 */
     599616000L,    /* 1989 */
     631152000L,    /* 1990 */
     662688000L,    /* 1991 */
     694224000L,    /* 1992 */
     725846400L,    /* 1993 */
     757382400L,    /* 1994 */
     788918400L,    /* 1995 */
     820454400L,    /* 1996 */
     852076800L,    /* 1997 */
     883612800L,    /* 1998 */
     915148800L,    /* 1999 */
     946684800L,    /* 2000 */
     978307200L,    /* 2001 */
    1009843200L,    /* 2002 */
    1041379200L,    /* 2003 */
    1072915200L,    /* 2004 */
    1104537600L,    /* 2005 */
    1136073600L,    /* 2006 */
    1167609600L,    /* 2007 */
    1199145600L,    /* 2008 */
    1230768000L,    /* 2009 */
    1262304000L,    /* 2010 */
    1293840000L,    /* 2011 */
    1325376000L,    /* 2012 */
    1356998400L,    /* 2013 */
    1388534400L,    /* 2014 */
    1420070400L,    /* 2015 */
    1451606400L,    /* 2016 */
    1483228800L,    /* 2017 */
    1514764800L,    /* 2018 */
    1546300800L,    /* 2019 */
    1577836800L,    /* 2020 */
    1609459200L,    /* 2021 */
    1640995200L,    /* 2022 */
    1672531200L,    /* 2023 */
    1704067200L,    /* 2024 */
    1735689600L,    /* 2025 */
    1767225600L,    /* 2026 */
    1798761600L,    /* 2027 */
    1830297600L,    /* 2028 */
    1861920000L,    /* 2029 */
    1893456000L,    /* 2030 */
    1924992000L,    /* 2031 */
    1956528000L,    /* 2032 */
    1988150400L,    /* 2033 */
    2019686400L,    /* 2034 */
    2051222400L,    /* 2035 */
    2082758400L,    /* 2036 */
    2114380800L,    /* 2037 */
    2145916800L     /* 2038 */
};

const char month_snames[12][4] = {
    "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};

void gm_timestr_822(char *ts, time_t sec)
{
    static const char *const days[7]=
       {"Sun","Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    struct tm *tms;
 
    tms = gmtime(&sec);
 
    sprintf(ts, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT", days[tms->tm_wday],
            tms->tm_mday, month_snames[tms->tm_mon], tms->tm_year + 1900,
            tms->tm_hour, tms->tm_min, tms->tm_sec);
}

void gm_timestr_850(char *ts, time_t sec)
{
    static const char *const days[7]=
 {"Sunday","Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
    struct tm *tms;
    int year;
 
    tms = gmtime(&sec);

    year = tms->tm_year;
    if (year >= 100) year -= 100;
 
    sprintf(ts, "%s, %.2d-%s-%.2d %.2d:%.2d:%.2d GMT", days[tms->tm_wday],
            tms->tm_mday, month_snames[tms->tm_mon], year,
            tms->tm_hour, tms->tm_min, tms->tm_sec);
}

void gm_timestr_ccc(char *ts, time_t sec)
{
    static const char *const days[7]=
       {"Sun","Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    struct tm *tms;
 
    tms = gmtime(&sec);
 
    sprintf(ts, "%s %s %2d %.2d:%.2d:%.2d %d", days[tms->tm_wday],
            month_snames[tms->tm_mon], tms->tm_mday, 
            tms->tm_hour, tms->tm_min, tms->tm_sec, tms->tm_year + 1900);
}

int main (void)
{
    int year, i;
    time_t guess;
    time_t offset = 0;
 /* time_t offset = 0; */
 /* time_t offset = ((31 + 28) * 24 * 3600) - 1; */
    time_t secstodate, newsecs;
    char datestr[50];

    for (year = 1970; year < 2038; ++year) {
        secstodate = (time_t)year2secs[year - 1970] + offset;
        gm_timestr_822(datestr, secstodate);
        newsecs = parseHTTPdate(datestr);
        if (secstodate == newsecs)
            printf("Yes %4d %11ld  %s\n", year, (long)secstodate, datestr);
        else if (newsecs == BAD_DATE)
            printf("No  %4d %11ld %11ld %s\n", year, (long)secstodate, 
                   (long)newsecs, datestr);
        else
            printf("No* %4d %11ld %11ld %s\n", year, (long)secstodate, 
                   (long)newsecs, datestr);
    }
    
    srand48(978245L);

    for (i = 0; i < 10000; ++i) {
        guess = (time_t)mrand48();
        if (guess < 0) guess *= -1;
        secstodate = guess + offset;
        gm_timestr_822(datestr, secstodate);
        newsecs = parseHTTPdate(datestr);
        if (secstodate == newsecs)
            printf("Yes %11ld  %s\n", (long)secstodate, datestr);
        else if (newsecs == BAD_DATE)
            printf("No  %11ld %11ld %s\n", (long)secstodate, 
                   (long)newsecs, datestr);
        else
            printf("No* %11ld %11ld %s\n", (long)secstodate, 
                   (long)newsecs, datestr);
    }
    exit(0);
}
