#include <windows.h>
#include <assert.h>

#include "httpd.h"

static void sub_canonical_filename(char *szCanon,const char *szFile)
{
    char buf[_MAX_PATH];
    int n;
    char *szFilePart;
    WIN32_FIND_DATA d;
    HANDLE h;

    n=GetFullPathName(szFile,sizeof buf,buf,&szFilePart);
    assert(n);
    assert(n < sizeof buf);

    if(!strchr(buf,'*') && !strchr(buf,'?'))
    {
	h=FindFirstFile(buf,&d);
        if(h != INVALID_HANDLE_VALUE)
	    FindClose(h);
    }
    else
	h=INVALID_HANDLE_VALUE;

    if(szFilePart < buf+3)
    {
	strcpy(szCanon,buf);
	szCanon[2]='/';
	return;
    }
    if(szFilePart != buf+3)
    {
	char b2[_MAX_PATH];
	assert(szFilePart > buf+3);

	szFilePart[-1]='\0';
	sub_canonical_filename(b2,buf);

	strcpy(szCanon,b2);
	strcat(szCanon,"/");
    }
    else
    {
	strcpy(szCanon,buf);
	szCanon[2]='/';
	szCanon[3]='\0';
    }
    if(h == INVALID_HANDLE_VALUE)
	strcat(szCanon,szFilePart);
    else
	strcat(szCanon,d.cFileName);
}

API_EXPORT(char *) os_canonical_filename(pool *pPool,const char *szFile)
{
    char buf[_MAX_PATH];

    sub_canonical_filename(buf,szFile);
    strlwr(buf);
    return pstrdup(pPool,buf);
}
