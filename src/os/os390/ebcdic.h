#include <sys/types.h>

extern const unsigned char os_toascii[256];
extern const unsigned char os_toebcdic[256];
void ebcdic2ascii(void *dest, const void *srce, size_t count);
void ascii2ebcdic(void *dest, const void *srce, size_t count);

/* Provide backward compatibility until all EBCDIC platforms
 * have switched to using ebcdic2ascii() only: 
 */
#define ebcdic2ascii_strictly(_to,_from,_len) ebcdic2ascii(_to,_from,_len)
