#if defined(__DATE__) && defined(__TIME__)
const char SERVER_BUILT[] = __DATE__ " " __TIME__;
#else
const char SERVER_BUILT[] = "unknown";
#endif
