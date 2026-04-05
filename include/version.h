/* Auto-generated - do not edit */

#ifndef MOD_HTTP3_VERSION_H
#define MOD_HTTP3_VERSION_H

#define MOD_HTTP3_VERSION_MAJOR 0
#define MOD_HTTP3_VERSION_MINOR 0
#define MOD_HTTP3_VERSION_PATCH 4

// Construct a 24-bit packed version number from major, minor and patch. Version 1.2.3 becomes 0x010203.
#define MOD_HTTP3_MAKE_VERSION(major, minor, patch) (((major) << 16) | ((minor) << 8) | (patch))

#define MOD_HTTP3_VERSION MOD_HTTP3_MAKE_VERSION(MOD_HTTP3_VERSION_MAJOR, MOD_HTTP3_VERSION_MINOR, MOD_HTTP3_VERSION_PATCH)

#define MOD_HTTP3_VERSION_STRING "0.0.4"

#endif
