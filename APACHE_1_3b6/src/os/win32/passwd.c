#include <stdio.h>
#include "passwd.h"

/* Very tacky implementation */

struct passwd *getpwnam(const char *szUser)
{
    static struct passwd pw;

    if(strlen(szUser) > _MAX_PATH-10)
	return NULL;

    sprintf(pw.pw_dir,"c:/users/%s",szUser);

    return &pw;
}
