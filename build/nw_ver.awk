BEGIN {

  # fetch Apache version numbers from input file and writes them to STDOUT

  while ((getline < ARGV[1]) > 0) {
    if (match ($0, /^#define AP_SERVER_MAJORVERSION "[^"]+"/)) {
      ver_major = substr($3, 2, length($3) - 2);
    }
    else if (match ($0, /^#define AP_SERVER_MINORVERSION "[^"]+"/)) {
      ver_minor = substr($3, 2, length($3) - 2);
    }
    else if (match ($0, /^#define AP_SERVER_PATCHLEVEL/)) {
      ver_str_patch = substr($3, 2, length($3) - 2);
      if (match (ver_str_patch, /[0-9][0-9]*/)) {
         ver_patch = substr(ver_str_patch, RSTART, RLENGTH); 
      }
    }
  }
  ver = ver_major "," ver_minor "," ver_patch;
  ver_str = ver_major "." ver_minor "." ver_str_patch;

  print "VERSION = " ver "";
  print "VERSION_STR = " ver_str "";

}
