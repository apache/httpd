#include <sys/types.h>

extern const char os_toascii[256];
extern const char os_toebcdic[256];
void ebcdic2ascii(unsigned char *dest, const unsigned char *srce, size_t count);
void ascii2ebcdic(unsigned char *dest, const unsigned char *srce, size_t count);

