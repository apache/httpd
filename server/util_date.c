/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000 The Apache Software Foundation.  All rights
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
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * Portions of this software are based upon public domain software
 * originally written at the National Center for Supercomputing Applications,
 * University of Illinois, Urbana-Champaign.
 */

/*
 * util_date.c: date parsing utility routines
 *     These routines are (hopefully) platform independent.
 * 
 * 27 Oct 1996  Roy Fielding
 *     Extracted (with many modifications) from mod_proxy.c and
 *     tested with over 50,000 randomly chosen valid date strings
 *     and several hundred variations of invalid date strings.
 * 
 */

#define CORE_PRIVATE

#include "ap_config.h"
#include "util_date.h"
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

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
API_EXPORT(int) ap_checkmask(const char *data, const char *mask)
{
    int i;
    char d;

    for (i = 0; i < 256; i++) {
	d = data[i];
	switch (mask[i]) {
	case '\0':
	    return (d == '\0');

	case '*':
	    return 1;

	case '@':
	    if (!ap_isupper(d))
		return 0;
	    break;
	case '$':
	    if (!ap_islower(d))
		return 0;
	    break;
	case '#':
	    if (!ap_isdigit(d))
		return 0;
	    break;
	case '&':
	    if (!ap_isxdigit(d))
		return 0;
	    break;
	case '~':
	    if ((d != ' ') && !ap_isdigit(d))
		return 0;
	    break;
	default:
	    if (mask[i] != d)
		return 0;
	    break;
	}
    }
    return 0;			/* We only get here if mask is corrupted (exceeds 256) */
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
API_EXPORT(apr_time_t) ap_parseHTTPdate(const char *date)
{
    ap_exploded_time_t ds;
    apr_time_t result;
    int mint, mon;
    const char *monstr, *timstr;
    static const int months[12] =
    {
	('J' << 16) | ('a' << 8) | 'n', ('F' << 16) | ('e' << 8) | 'b',
	('M' << 16) | ('a' << 8) | 'r', ('A' << 16) | ('p' << 8) | 'r',
	('M' << 16) | ('a' << 8) | 'y', ('J' << 16) | ('u' << 8) | 'n',
	('J' << 16) | ('u' << 8) | 'l', ('A' << 16) | ('u' << 8) | 'g',
	('S' << 16) | ('e' << 8) | 'p', ('O' << 16) | ('c' << 8) | 't',
	('N' << 16) | ('o' << 8) | 'v', ('D' << 16) | ('e' << 8) | 'c'};

    if (!date)
	return BAD_DATE;

    while (*date && ap_isspace(*date))	/* Find first non-whitespace char */
	++date;

    if (*date == '\0') 
	return BAD_DATE;

    if ((date = strchr(date, ' ')) == NULL)	/* Find space after weekday */
	return BAD_DATE;

    ++date;			/* Now pointing to first char after space, which should be */
    /* start of the actual date information for all 3 formats. */

    if (ap_checkmask(date, "## @$$ #### ##:##:## *")) {	/* RFC 1123 format */
	ds.tm_year = ((date[7] - '0') * 10 + (date[8] - '0') - 19) * 100;
	if (ds.tm_year < 0)
	    return BAD_DATE;

	ds.tm_year += ((date[9] - '0') * 10) + (date[10] - '0');

	ds.tm_mday = ((date[0] - '0') * 10) + (date[1] - '0');

	monstr = date + 3;
	timstr = date + 12;
    }
    else if (ap_checkmask(date, "##-@$$-## ##:##:## *")) {		/* RFC 850 format  */
	ds.tm_year = ((date[7] - '0') * 10) + (date[8] - '0');
	if (ds.tm_year < 70)
	    ds.tm_year += 100;

	ds.tm_mday = ((date[0] - '0') * 10) + (date[1] - '0');

	monstr = date + 3;
	timstr = date + 10;
    }
    else if (ap_checkmask(date, "@$$ ~# ##:##:## ####*")) {	/* asctime format  */
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
    else 
	return BAD_DATE;

    if (ds.tm_mday <= 0 || ds.tm_mday > 31)
	return BAD_DATE;

    ds.tm_hour = ((timstr[0] - '0') * 10) + (timstr[1] - '0');
    ds.tm_min = ((timstr[3] - '0') * 10) + (timstr[4] - '0');
    ds.tm_sec = ((timstr[6] - '0') * 10) + (timstr[7] - '0');

    if ((ds.tm_hour > 23) || (ds.tm_min > 59) || (ds.tm_sec > 61)) 
	return BAD_DATE;

    mint = (monstr[0] << 16) | (monstr[1] << 8) | monstr[2];
    for (mon = 0; mon < 12; mon++)
	if (mint == months[mon])
	    break;
    if (mon == 12)
	return BAD_DATE;

    if ((ds.tm_mday == 31) && (mon == 3 || mon == 5 || mon == 8 || mon == 10))
	return BAD_DATE;

    /* February gets special check for leapyear */

    if ((mon == 1) &&
	((ds.tm_mday > 29)
	 || ((ds.tm_mday == 29)
	     && ((ds.tm_year & 3)
		 || (((ds.tm_year % 100) == 0)
		     && (((ds.tm_year % 400) != 100)))))))
	return BAD_DATE;

    ds.tm_mon = mon;

    /* ap_mplode_time uses tm_usec and tm_gmtoff fields, but they haven't 
     * been set yet. 
     * It should be safe to just zero out these values.
     * tm_usec is the number of microseconds into the second.  HTTP only
     * cares about second granularity.
     * tm_gmtoff is the number of seconds off of GMT the time is.  By
     * definition all times going through this function are in GMT, so this
     * is zero. 
     */
    ds.tm_usec = 0;
    ds.tm_gmtoff = 0;
    if (apr_implode_time(&result, &ds) != APR_SUCCESS) 
	return BAD_DATE;
    
    return result;
}
