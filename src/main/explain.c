#include <stdio.h>
#include <stdarg.h>
#include "explain.h"

void _Explain(const char *szFile,int nLine,const char *szFmt,...)
    {
    va_list vlist;

    fprintf(stderr,"%s(%d): ",szFile,nLine);
    va_start(vlist,szFmt);
    vfprintf(stderr,szFmt,vlist);
    va_end(vlist);
    fputc('\n',stderr);
    }
