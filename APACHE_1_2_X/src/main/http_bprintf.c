/*
 * printf() style routines stolen from FastCGI
 * Copyright (c) 1996 Open Market, Inc.
 */

/*
 * Modified to work with Apache buffering routines by Ben Laurie
 * <ben@algroup.co.uk>.
 *
 * Modifications Copyright (C) 1996 Ben Laurie.
 *
 * History:
 * 18 May 1996 Initial revision [Ben Laurie]
 *
 */

#include <assert.h>
#include <math.h>
#include "conf.h"
#include "alloc.h"
#include "buff.h"

#if !defined(max)
#define max(a,b)	(a > b ? a : b)
#endif

#ifdef NO_LONG_DOUBLE
#define LONG_DOUBLE	double
#else
#define LONG_DOUBLE	long double
#endif

#define FALSE	0
#define TRUE	1

#define PRINTF_BUFFLEN 100
    /*
     * More than sufficient space for all unmodified conversions
     * except %s and %f.
     */
#define FMT_BUFFLEN 25
    /*
     * Max size of a format specifier is 1 + 5 + 7 + 7 + 2 + 1 + slop
     */
#define NULL_STRING "(null)"
    /*
     * String displayed if given a NULL pointer.
     */

/*
 * Copy n characters from *srcPtr to *destPtr, then increment
 * both *srcPtr and *destPtr by n.
 */
static void CopyAndAdvance(char **destPtr, const char **srcPtr, int n)
    {
    char *dest = *destPtr;
    const char *src = *srcPtr;
    int i;
    
    for (i = 0; i < n; i++)
        *dest++ = *src++;
    *destPtr = dest;
    *srcPtr = src;
    }

int vbprintf(BUFF *bp, const char *format, va_list arg)
    {
    const char *f,*fStop,*percentPtr,*p;
    char *fmtBuffPtr, *buffPtr;
    int op, performedOp, sizeModifier, buffLen, specifierLength;
    int fastPath, n, buffReqd, minWidth, precision, exp;
    int buffCount = 0;
    int auxBuffLen = 0;
    char *auxBuffPtr = NULL;
    int streamCount = 0;
    char fmtBuff[FMT_BUFFLEN];
    char buff[PRINTF_BUFFLEN];

    int intArg;
    short shortArg;
    long longArg;
    unsigned unsignedArg;
    unsigned long uLongArg;
    unsigned short uShortArg;
    char *charPtrArg = NULL;
    void *voidPtrArg;
    int *intPtrArg;
    long *longPtrArg;
    short *shortPtrArg;
    double doubleArg = 0.0;
    LONG_DOUBLE lDoubleArg = 0.0;

    fmtBuff[0] = '%';
    f=format;
    fStop = f + strlen(f);
    while (f != fStop)
	{
        percentPtr = memchr(f, '%', fStop - f);
        if(percentPtr == NULL) percentPtr = fStop;
        if(percentPtr != f)
	    {
            if(bwrite(bp,f,percentPtr - f) < 0)
		goto ErrorReturn;
            streamCount += percentPtr - f;
            f = percentPtr;
            if(f == fStop)
		break;
	    }
        fastPath = TRUE;
        /*
         * The following loop always executes either once or twice.
         */
        for (;;)
	    {
            if(fastPath)
		{
                /*
                 * Fast path: Scan optimistically, hoping that no flags,
                 * minimum field width, or precision are specified.
                 * Use the preallocated buffer, which is large enough
                 * for all fast path cases.  If the conversion specifier
                 * is really more complex, run the loop a second time
                 * using the slow path.
                 * Note that fast path execution of %s bypasses the buffer
                 * and %f is not attempted on the fast path due to
                 * its large buffering requirements.
                 */
                op = percentPtr[1];
                switch(op)
		    {
	        case 'l':
	        case 'L':
                case 'h':
		    sizeModifier = op;
		    op = percentPtr[2];
		    fmtBuff[1] = sizeModifier;
		    fmtBuff[2] = op;
		    fmtBuff[3] = '\0';
		    specifierLength = 3;
		    break;
	        default:
		    sizeModifier = ' ';
		    fmtBuff[1] = op;
		    fmtBuff[2] = '\0';
		    specifierLength = 2;
		    break;
		    }
                buffPtr = buff;
                buffLen = PRINTF_BUFFLEN;
		}
	    else
		{
                /*
                 * Slow path: Scan the conversion specifier and construct
                 * a new format string, compute an upper bound on the
                 * amount of buffering that sprintf will require,
                 * and allocate a larger buffer if necessary.
                 */
                p = percentPtr + 1;
                fmtBuffPtr = &fmtBuff[1];
                /*
                 * Scan flags
                 */
                n = strspn(p, "-0+ #");
                if(n > 5)
		    goto ErrorReturn;
                CopyAndAdvance(&fmtBuffPtr, &p, n);

		/* Optimiser bug in SCO 5 - p is not advanced here under -O2.
		 * -K noinline fixes it. Ben.
		 */

                /*
                 * Scan minimum field width
                 */
                n = strspn(p, "0123456789");
                if(n == 0)
		    {
                    if(*p == '*')
			{
                        minWidth = va_arg(arg, int);
                        if(abs(minWidth) > 999999) goto ErrorReturn;
			/*
			 * The following use of strlen rather than the
			 * value returned from sprintf is because SUNOS4
			 * returns a char * instead of an int count.
			 */
			sprintf(fmtBuffPtr, "%d", minWidth);
                        fmtBuffPtr += strlen(fmtBuffPtr);
                        p++;
			}
		    else
                        minWidth = 0;
		    }
		else if(n <= 6)
		    {
                    minWidth = strtol(p, NULL, 10);
                    CopyAndAdvance(&fmtBuffPtr, &p, n);
		    }
		else
                    goto ErrorReturn;
                /*
                 * Scan precision
                 */
	        if(*p == '.')
		    {
                    p++;
                    n = strspn(p, "0123456789");
                    if(n == 0)
			{
                        if(*p == '*')
			    {
                            precision = va_arg(arg, int);
                            if(precision < 0) precision = 0;
                            if(precision > 999999) goto ErrorReturn;
			    /*
			     * The following use of strlen rather than the
			     * value returned from sprintf is because SUNOS4
			     * returns a char * instead of an int count.
			     */
			    sprintf(fmtBuffPtr, ".%d", precision);
			    fmtBuffPtr += strlen(fmtBuffPtr);
                            p++;
			    }
			else
                            precision = 0;
			}
		    else if(n <= 6)
			{
                        precision = strtol(p, NULL, 10);
			*fmtBuffPtr++='.';
                        CopyAndAdvance(&fmtBuffPtr, &p, n);
			}
		    else
                        goto ErrorReturn;
		    }
		else
                    precision = -1;
                /*
                 * Scan size modifier and conversion operation
                 */
                switch(*p)
		    {
	        case 'l':
                case 'L':
                case 'h':
		    sizeModifier = *p;
		    CopyAndAdvance(&fmtBuffPtr, &p, 1);
		    break;
	        
		default:
		    sizeModifier = ' ';
		    break;
		    }
                op = *p;
                CopyAndAdvance(&fmtBuffPtr, &p, 1);
                assert(fmtBuffPtr - fmtBuff < FMT_BUFFLEN);
                *fmtBuffPtr = '\0';
		/*
		bwrite(bp,"[",1);
		bwrite(bp,fmtBuff,strlen(fmtBuff));
		bwrite(bp,"]",1);
		*/
                specifierLength = p - percentPtr;
                /*
                 * Bound the required buffer size.  For s and f
                 * conversions this requires examining the argument.
                 */
                switch(op)
		    {
	        case 'd':
                case 'i':
                case 'u':
                case 'o':
                case 'x':
                case 'X':
                case 'c':
                case 'p':
		    buffReqd = max(precision, 46);
		    break;

		case 's':
		    charPtrArg = va_arg(arg, char *);
		    if (charPtrArg == NULL) {
			charPtrArg = NULL_STRING;
		    };
		    if(precision == -1)
			buffReqd = strlen(charPtrArg);
		    else
			{
			p = memchr(charPtrArg, '\0', precision);
			if (p == NULL)
				buffReqd = precision;
			else
				buffReqd = p - charPtrArg;
			}
		    break;

	        case 'f':
		    switch(sizeModifier)
			{
		    case ' ':
		        doubleArg = va_arg(arg, double);
			frexp(doubleArg, &exp);
			break;

		    case 'L':
		        lDoubleArg = va_arg(arg, LONG_DOUBLE);
			frexp(lDoubleArg, &exp);
			break;

		    default:
		        goto ErrorReturn;
                        }
		    if(precision == -1)
			precision = 6;
		    buffReqd = precision + 3 + ((exp > 0) ? exp/3 : 0);
		    break;
	            
		case 'e':
	        case 'E':
	        case 'g':
	        case 'G':
		    if(precision == -1)
			precision = 6;
		    buffReqd = precision + 8;
		    break;

	        case 'n':
	        case '%':
	        default:
		    goto ErrorReturn;
		    }
                buffReqd = max(buffReqd + 10, minWidth);
                /*
                 * Allocate the buffer
                 */
	        if(buffReqd <= PRINTF_BUFFLEN)
		    {
                    buffPtr = buff;
		    buffLen = PRINTF_BUFFLEN;
		    }
		else
		    {
                    if(auxBuffPtr == NULL || buffReqd > auxBuffLen)
			{
		        if(auxBuffPtr != NULL) free(auxBuffPtr);
                        auxBuffPtr = malloc(buffReqd);
                        auxBuffLen = buffReqd;
                        if(auxBuffPtr == NULL)
			    goto ErrorReturn;
			}
                    buffPtr = auxBuffPtr;
		    buffLen = auxBuffLen;
		    }
		}
            /*
             * This giant switch statement requires the following variables
             * to be set up: op, sizeModifier, arg, buffPtr, fmtBuff.
             * When fastPath == FALSE and op == 's' or 'f', the argument
             * has been read into charPtrArg, doubleArg, or lDoubleArg.
             * The statement produces the boolean performedOp, TRUE iff
             * the op/sizeModifier were executed and argument consumed;
             * if performedOp, the characters written into buffPtr[]
             * and the character count buffCount (== EOF meaning error).
             *
             * The switch cases are arranged in the same order as in the
             * description of fprintf in section 15.11 of Harbison and Steele.
             */
            performedOp = TRUE;
            switch(op)
		{
	    case 'd':
	    case 'i':
	        switch(sizeModifier)
		    {
		case ' ':
		    intArg = va_arg(arg, int);
		    sprintf(buffPtr, fmtBuff, intArg);
		    buffCount = strlen(buffPtr);
		    break;
		
		case 'l':
		    longArg = va_arg(arg, long);
		    sprintf(buffPtr, fmtBuff, longArg);
		    buffCount = strlen(buffPtr);
		    break;
	            
		case 'h':
		    shortArg = va_arg(arg, short);
		    sprintf(buffPtr, fmtBuff, shortArg);
		    buffCount = strlen(buffPtr);
		    break;
		
		default:
		    goto ErrorReturn;
	            }
		break;

	    case 'u':
	    case 'o':
	    case 'x':
	    case 'X':
		switch(sizeModifier)
		    {
		case ' ':
		    unsignedArg = va_arg(arg, unsigned);
		    sprintf(buffPtr, fmtBuff, unsignedArg);
		    buffCount = strlen(buffPtr);
		    break;
		
		case 'l':
		    uLongArg = va_arg(arg, unsigned long);
		    sprintf(buffPtr, fmtBuff, uLongArg);
		    buffCount = strlen(buffPtr);
		    break;
		
		case 'h':
		    uShortArg = va_arg(arg, unsigned short);
		    sprintf(buffPtr, fmtBuff, uShortArg);
		    buffCount = strlen(buffPtr);
		    break;
		
		default:
		    goto ErrorReturn;
                    }
		break;

	    case 'c':
		switch(sizeModifier)
		    {
		case ' ':
		    intArg = va_arg(arg, int);
		    sprintf(buffPtr, fmtBuff, intArg);
		    buffCount = strlen(buffPtr);
		    break;

		case 'l':
		    /*
		     * XXX: Allowed by ISO C Amendment 1, but
		     * many platforms don't yet support wint_t
		     */
		    goto ErrorReturn;

		default:
		    goto ErrorReturn;
                    }
		break;

	    case 's':
		switch(sizeModifier)
		    {
		case ' ':
		    if(fastPath)
			{
			buffPtr = va_arg(arg, char *);
			if (buffPtr == NULL) {
			    buffPtr = NULL_STRING;
			};
			buffCount = strlen(buffPtr);
			buffLen = buffCount + 1;
			}
		    else
			{
			sprintf(buffPtr, fmtBuff, charPtrArg);
			buffCount = strlen(buffPtr);
			}
		    break;

		case 'l':
		    /*
		     * XXX: Don't know how to convert a sequence
		     * of wide characters into a byte stream, or
		     * even how to predict the buffering required.
		     */
		    goto ErrorReturn;

		default:
		    goto ErrorReturn;
                    }
		break;

	    case 'p':
		if(sizeModifier != ' ')
		    goto ErrorReturn;
		voidPtrArg = va_arg(arg, void *);
		sprintf(buffPtr, fmtBuff, voidPtrArg);
		buffCount = strlen(buffPtr);
		break;

	    case 'n':
		switch(sizeModifier)
		    {
		case ' ':
		    intPtrArg = va_arg(arg, int *);
		    *intPtrArg = streamCount;
		    break;

		case 'l':
		    longPtrArg = va_arg(arg, long *);
		    *longPtrArg = streamCount;
		    break;

		case 'h':
		    shortPtrArg = va_arg(arg, short *);
		    *shortPtrArg = streamCount;
		    break;

		default:
		    goto ErrorReturn;
	            }
		buffCount = 0;
		break;

	    case 'f':
		if(fastPath)
		    {
		    performedOp = FALSE;
		    break;
		    }

		switch(sizeModifier)
		    {
		case ' ':
		    sprintf(buffPtr, fmtBuff, doubleArg);
		    buffCount = strlen(buffPtr);
		    break;

		case 'L':
		    sprintf(buffPtr, fmtBuff, lDoubleArg);
		    buffCount = strlen(buffPtr);
		    break;

		default:
		    goto ErrorReturn;
                    }
		break;
		/* FIXME: Used to flow through here? Should it? Ben */

	    case 'e':
	    case 'E':
	    case 'g':
	    case 'G':
		switch(sizeModifier)
		    {
		case ' ':
		    doubleArg = va_arg(arg, double);
		    sprintf(buffPtr, fmtBuff, doubleArg);
		    buffCount = strlen(buffPtr);
		    break;

		case 'L':
		    lDoubleArg = va_arg(arg, LONG_DOUBLE);
		    sprintf(buffPtr, fmtBuff, lDoubleArg);
		    buffCount = strlen(buffPtr);
		    break;

		default:
		    goto ErrorReturn;
                    }
		break;

	    case '%':
		if(sizeModifier != ' ')
		    goto ErrorReturn;
		buff[0] = '%';
		buffCount = 1;
		break;

	    case '\0':
		goto ErrorReturn;

	    default:
		performedOp = FALSE;
		break;
		} /* switch(op) */

            if(performedOp)
		break;
            if(!fastPath)
		goto ErrorReturn;
            fastPath = FALSE;
	    } /* for (;;) */
        assert(buffCount < buffLen);
        if(buffCount > 0)
	    {
            if(bwrite(bp,buffPtr,buffCount) < 0)
                goto ErrorReturn;
            streamCount += buffCount;
	    }
	else if(buffCount < 0)
            goto ErrorReturn;
        f += specifierLength;
	} /* while(f != fStop) */
    goto NormalReturn;
ErrorReturn:
    streamCount = -1;
NormalReturn:
    if(auxBuffPtr != NULL)
	free(auxBuffPtr);
    return streamCount;
    }
