/* ====================================================================
 * Copyright (c) 1996,1997 The Apache Group.  All rights reserved.
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
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * util_date.c: date parsing utility routines
 *     These routines are (hopefully) platform-independent.
 * 
 * 27 Oct 1996  Roy Fielding
 *     Extracted (with many modifications) from mod_proxy.c and
 *     tested with over 50,000 randomly chosen valid date strings
 *     and several hundred variations of invalid date strings.
 * 
 */

#include "util_date.h"
#include <ctype.h>
#include <string.h>

/*
 * Compare a string to a mask
 * Mask characters (arbitrary maximum is 256 characters, just in case):
 *   @ - uppercase letter
 *   $ - lowercase letter
 *   & - hex digit
 *   # - digit
 *   ~ - digit or space
 *   * - swallow remaining characters 
 *  <x> - exact match for any other character
 */
int checkmask(const char *data, const char *mask)
{
    int i;
    char d;

    for (i = 0; i < 256; i++) {
        d  = data[i];
        switch (mask[i]) {
          case '\0': return (d == '\0');

          case '*':  return 1;

          case '@':  if (!isupper(d)) return 0;
                     break;
          case '$':  if (!islower(d)) return 0;
                     break;
          case '#':  if (!isdigit(d)) return 0;
                     break;
          case '&':  if (!isxdigit(d)) return 0;
                     break;
          case '~':  if ((d != ' ') && !isdigit(d)) return 0;
                     break;
          default:   if (mask[i] != d) return 0;
                     break;
        }
    }
    return 0;  /* We only get here if mask is corrupted (exceeds 256) */
}

/*
 * tm2sec converts a GMT tm structure into the number of seconds since
 * 1st January 1970 UT.  Note that we ignore tm_wday, tm_yday, and tm_dst.
 * 
 * The return value is always a valid time_t value -- (time_t)0 is returned
 * if the input date is outside that capable of being represented by time(),
 * i.e., before Thu, 01 Jan 1970 00:00:00 for all systems and 
 * beyond 2038 for 32bit systems.
 *
 * This routine is intended to be very fast, much faster than mktime().
 */
time_t tm2sec(const struct tm *t)
{
    int  year;
    time_t days;
    const int dayoffset[12] =
        {306, 337, 0, 31, 61, 92, 122, 153, 184, 214, 245, 275};

    year = t->tm_year;

    if (year < 70 || ((sizeof(time_t) <= 4) && (year >= 138)))
        return BAD_DATE;

    /* shift new year to 1st March in order to make leap year calc easy */

    if (t->tm_mon < 2) year--;

    /* Find number of days since 1st March 1900 (in the Gregorian calendar). */

    days  = year * 365 + year/4 - year/100 + (year/100 + 3)/4;
    days += dayoffset[t->tm_mon] + t->tm_mday - 1;
    days -= 25508; /* 1 jan 1970 is 25508 days since 1 mar 1900 */

    days = ((days * 24 + t->tm_hour) * 60 + t->tm_min) * 60 + t->tm_sec;

    if (days < 0)
        return BAD_DATE;       /* must have overflowed */
    else
        return days;           /* must be a valid time */
}

/*
 * Parses an HTTP date in one of three standard forms:
 *
 *     Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
 *     Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
 *     Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format
 *
 * and returns the time_t number of seconds since 1 Jan 1970 GMT, or
 * 0 if this would be out of range or if the date is invalid.
 *
 * The restricted HTTP syntax is
 * 
 *     HTTP-date    = rfc1123-date | rfc850-date | asctime-date
 *
 *     rfc1123-date = wkday "," SP date1 SP time SP "GMT"
 *     rfc850-date  = weekday "," SP date2 SP time SP "GMT"
 *     asctime-date = wkday SP date3 SP time SP 4DIGIT
 *
 *     date1        = 2DIGIT SP month SP 4DIGIT
 *                    ; day month year (e.g., 02 Jun 1982)
 *     date2        = 2DIGIT "-" month "-" 2DIGIT
 *                    ; day-month-year (e.g., 02-Jun-82)
 *     date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
 *                    ; month day (e.g., Jun  2)
 *
 *     time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
 *                    ; 00:00:00 - 23:59:59
 *
 *     wkday        = "Mon" | "Tue" | "Wed"
 *                  | "Thu" | "Fri" | "Sat" | "Sun"
 *
 *     weekday      = "Monday" | "Tuesday" | "Wednesday"
 *                  | "Thursday" | "Friday" | "Saturday" | "Sunday"
 *
 *     month        = "Jan" | "Feb" | "Mar" | "Apr"
 *                  | "May" | "Jun" | "Jul" | "Aug"
 *                  | "Sep" | "Oct" | "Nov" | "Dec"
 *
 * However, for the sake of robustness (and Netscapeness), we ignore the
 * weekday and anything after the time field (including the timezone).
 *
 * This routine is intended to be very fast; 10x faster than using sscanf.
 *
 * Originally from Andrew Daviel <andrew@vancouver-webpages.com>, 29 Jul 96
 * but many changes since then.
 *
 */
time_t parseHTTPdate(const char *date)
{
    struct tm ds;
    int mint, mon;
    const char *monstr, *timstr;
    const int months[12] = {
        ('J' << 16) | ( 'a' << 8) | 'n',  ('F' << 16) | ( 'e' << 8) | 'b',
        ('M' << 16) | ( 'a' << 8) | 'r',  ('A' << 16) | ( 'p' << 8) | 'r',
        ('M' << 16) | ( 'a' << 8) | 'y',  ('J' << 16) | ( 'u' << 8) | 'n',
        ('J' << 16) | ( 'u' << 8) | 'l',  ('A' << 16) | ( 'u' << 8) | 'g',
        ('S' << 16) | ( 'e' << 8) | 'p',  ('O' << 16) | ( 'c' << 8) | 't',
        ('N' << 16) | ( 'o' << 8) | 'v',  ('D' << 16) | ( 'e' << 8) | 'c'};

    if (!date)
        return BAD_DATE;

    while (*date && isspace(*date))      /* Find first non-whitespace char */
        ++date;

    if (*date == '\0')
        return BAD_DATE;

    if ((date = strchr(date,' ')) == NULL)   /* Find space after weekday */
        return BAD_DATE;

    ++date;    /* Now pointing to first char after space, which should be */
               /* start of the actual date information for all 3 formats. */
    
    if (checkmask(date, "## @$$ #### ##:##:## *")) {     /* RFC 1123 format */
        ds.tm_year = ((date[7] - '0') * 10 + (date[8] - '0') - 19) * 100;
        if (ds.tm_year < 0)
            return BAD_DATE;

        ds.tm_year += ((date[9] - '0') * 10) + (date[10] - '0');

        ds.tm_mday  = ((date[0] - '0') * 10) + (date[1] - '0');

        monstr = date + 3;
        timstr = date + 12;
    }
    else if (checkmask(date, "##-@$$-## ##:##:## *")) {  /* RFC 850 format  */
        ds.tm_year = ((date[7] - '0') * 10) + (date[8] - '0');
        if (ds.tm_year < 70)
            ds.tm_year += 100;

        ds.tm_mday = ((date[0] - '0') * 10) + (date[1] - '0');

        monstr = date + 3;
        timstr = date + 10;
    }
    else if (checkmask(date, "@$$ ~# ##:##:## ####*")) { /* asctime format  */
        ds.tm_year = ((date[16] - '0') * 10 + (date[17] - '0') - 19) * 100;
        if (ds.tm_year < 0)
            return BAD_DATE;

        ds.tm_year += ((date[18] - '0') * 10) + (date[19] - '0');

        if (date[4] == ' ')
            ds.tm_mday = 0;
        else
            ds.tm_mday = (date[4] - '0') * 10;

        ds.tm_mday += (date[5] - '0');

        monstr = date;
        timstr = date + 7;
    }
    else return BAD_DATE;

    if (ds.tm_mday <= 0 || ds.tm_mday > 31)
        return BAD_DATE;

    ds.tm_hour = ((timstr[0] - '0') * 10) + (timstr[1] - '0');
    ds.tm_min  = ((timstr[3] - '0') * 10) + (timstr[4] - '0');
    ds.tm_sec  = ((timstr[6] - '0') * 10) + (timstr[7] - '0');

    if ((ds.tm_hour > 23) || (ds.tm_min > 59) || (ds.tm_sec > 61))
        return BAD_DATE;

    mint = (monstr[0] << 16) | (monstr[1] << 8) | monstr[2];
    for (mon=0; mon < 12; mon++)
        if (mint == months[mon])
            break;
    if (mon == 12)
        return BAD_DATE;
    
    if ((ds.tm_mday == 31) && (mon == 3 || mon == 5 || mon == 8 || mon == 10))
        return BAD_DATE;

    /* February gets special check for leapyear */

    if ((mon == 1) && ((ds.tm_mday > 29) ||
         ((ds.tm_mday == 29) && ((ds.tm_year & 3) ||
           (((ds.tm_year % 100) == 0) && (((ds.tm_year % 400) != 100)))))))
        return BAD_DATE;

    ds.tm_mon = mon;

    return tm2sec(&ds);
}

