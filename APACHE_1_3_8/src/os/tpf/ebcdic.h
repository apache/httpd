#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void ebcdic2ascii(void *dest, const void *srce, size_t count);
void ebcdic2ascii_strictly(unsigned char *dest, const unsigned char *srce, size_t count);
void ascii2ebcdic(void *dest, const void *srce, size_t count);

