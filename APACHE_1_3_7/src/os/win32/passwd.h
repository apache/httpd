#include <stdlib.h>

struct passwd
{
    char pw_dir[_MAX_PATH];
};

struct passwd *getpwnam(const char *szUser);
