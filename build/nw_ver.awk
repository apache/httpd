BEGIN {

  # fetch Apache version numbers from input file and writes them to STDOUT

  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define AP_SERVER_MAJORVERSION_NUMBER /)) {
      ver_major = $3;
    }
    else if (match ($0, /^#define AP_SERVER_MINORVERSION_NUMBER /)) {
      ver_minor = $3;
    }
    else if (match ($0, /^#define AP_SERVER_PATCHLEVEL_NUMBER/)) {
      ver_patch = $3;
    }
    else if (match ($0, /^#define AP_SERVER_ADD_STRING /)) {
        ver_str_release = substr($3, 2, length($3) - 2);
    }
  }
  ver = ver_major "," ver_minor "," ver_patch;
  ver_str = ver_major "." ver_minor "." ver_patch ver_str_release;

  print "VERSION = " ver "";
  print "VERSION_STR = " ver_str "";

}
