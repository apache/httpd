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
   stub for gettimeofday():
      gettimeofday() is UNIX, not POSIX
*/

/*-------------------------------------------------------------------*/
/*                                                                   */
/* gettimeofday                                                      */
/*                                                                   */
/*-------------------------------------------------------------------*/
/*                                                                   */
/* #include <time.h>                                                 */
/*                                                                   */
/* int gettimeofday(                                                 */
/*      struct timeval *tp,                                          */
/*      struct timezone *tzp,                                        */
/* );                                                                */
/*                                                                   */
/*-------------------------------------------------------------------*/
/*                                                                   */
/* This function returns seconds and microseconds since midnight     */
/* January 1, 1970. The microseconds is actually only accurate to    */
/* the millisecond.                                                  */
/*                                                                   */
/* Note: To pick up the definitions of structs timeval and timezone  */
/*       from the <time.h> include file, the directive               */
/*       _SOCKET_SOURCE must be used.                                */
/*                                                                   */
/*-------------------------------------------------------------------*/
/*                                                                   */
/* RETURN VALUE                                                      */
/* A 0 return value indicates that the call succeeded.  A -1 return  */
/* value indicates an error occurred; errno is set to indicate the   */
/* error.                                                            */
/*                                                                   */
/*-------------------------------------------------------------------*/
/*                                                                   */
/* ERRORS                                                            */
/* EFAULT     not implemented yet.                                   */
/*                                                                   */
/*-------------------------------------------------------------------*/
/* Changes:                                                          */
/*   2-91    DR.  Created.                                           */
/*                                                                   */
/*-------------------------------------------------------------------*/


/* need _SOCKET_SOURCE to pick up structs timeval and timezone in time.h */
#ifndef _SOCKET_SOURCE
# define _SOCKET_SOURCE
#endif

#include <time.h>        /* structs timeval & timezone,
                            difftime(), localtime(), mktime(), time() */

#pragma intrinsic  TIMER



int
gettimeofday(struct timeval *tp, struct timezone *tpz)
{
   static unsigned long    basetime        = 0;
   static int              dsttime         = 0;
   static int              minuteswest     = 0;
   static int              oldtime         = 0;
   register int            newtime;
   int TIMER();


   /*-------------------------------------------------------------------*/
   /* Setup a base from which all future time will be computed.         */
   /*-------------------------------------------------------------------*/
   if ( basetime == 0 )
   {
      time_t    gmt_time;
      time_t    loc_time;
      struct tm *loc_time_tm;

      gmt_time    = time( NULL );
      loc_time_tm = localtime( &gmt_time ) ;
      loc_time    = mktime( loc_time_tm );

      oldtime     = TIMER();
      basetime    = (unsigned long) ( loc_time - (oldtime/1000) );

      /*----------------------------------------------------------------*/
      /* The calling process must be restarted if timezone or dst       */
      /* changes.                                                       */
      /*----------------------------------------------------------------*/
      minuteswest = (int) (difftime( loc_time, gmt_time ) / 60);
      dsttime     = loc_time_tm->tm_isdst;
   }

   /*-------------------------------------------------------------------*/
   /* Get the new time value. The timer value rolls over every 24 days, */
   /* so if the delta is negative, the basetime value is adjusted.      */
   /*-------------------------------------------------------------------*/
   newtime = TIMER();
   if ( newtime < oldtime )  basetime += 2073600;
   oldtime = newtime;

   /*-------------------------------------------------------------------*/
   /* Return the timestamp info.                                        */
   /*-------------------------------------------------------------------*/
   tp->tv_sec          = basetime + newtime/1000;
   tp->tv_usec         = (newtime%1000) * 1000;   /* only accurate to milli */
   if (tpz)
   {
      tpz->tz_minuteswest = minuteswest;
      tpz->tz_dsttime     = dsttime;
   }

   return 0;

} /* gettimeofday() */
