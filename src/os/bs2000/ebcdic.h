#include <sys/types.h>

extern const char _toascii[256];
extern const char _toebcdic[256];
void ebcdic2ascii(unsigned char *dest, const unsigned char *srce, size_t count);
void ascii2ebcdic(unsigned char *dest, const unsigned char *srce, size_t count);

