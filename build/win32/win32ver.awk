BEGIN {

  # ff bits: 1(debug), 2(prerelease), 4(patched), 8(vendor) and 32(special)
  # debug is summed based on the /Define _DEBUG
  # prerelease is based on the -dev extension,
  # patched is based on a non-standard "-ver" extension, 
  # special and vendor are toggled by their args.
  #
  ff = 0;

  file=ARGV[1];
  desc=ARGV[2];
  rel_h=ARGV[3];

  i = 4;
  while (length(ARGV[i])) {
    if (match(ARGV[i], /icon=/)) {
      icon = substr(ARGV[i], 6);
    }
    if (match(ARGV[i], /vendor=/)) {
      vendor = substr(ARGV[i], 8);
      ff = ff + 8;
    }
    if (match(ARGV[i], /special=/)) {
      special = substr(ARGV[i], 9);
      ff = ff + 32;
    }
    i = i + 1
  }

  i = i - 1;
  while (i) {
    delete ARGV[i];
    i = i - 1;
  }

  while ((getline < rel_h) > 0) {
    if (match ($0, /^#define AP_SERVER_BASEREVISION "[^"]+"/)) {
      ver = substr($0, RSTART + 32, RLENGTH - 33);
    }
  }

  verc = ver;
  gsub(/\./, ",", verc);
  if (build) {
    sub(/-.*/, "", verc)
    verc = verc "," build;
  } else if (sub(/-dev/, ",0", verc)) {
      ff = ff + 2;
  } else if (!sub(/-alpha/, ",10", verc)  \
          && !sub(/-beta/, ",100", verc)  \
          && !sub(/-gold/, ",200", verc)) {
    sub(/-.*/, "", verc);
    verc = verc "," 0;
  }
  
  if (length(vendor)) {
    ff = ff + 8;
  }

  if (length(icon)) {
    print "1 ICON DISCARDABLE \"" icon "\"";
  }
  print "1 VERSIONINFO";
  print " FILEVERSION " verc "";
  print " PRODUCTVERSION " verc "";
  print " FILEFLAGSMASK 0x3fL";
  print "#if defined(_DEBUG)"
  print " FILEFLAGS 0x" sprintf("%02x", ff + 1) "L";
  print "#else"
  print " FILEFLAGS 0x" sprintf("%02x", ff) "L";
  print "#endif"
  print " FILEOS 0x40004L";
  print " FILETYPE 0x1L";
  print " FILESUBTYPE 0x0L";
  print "BEGIN";
  print "  BLOCK \"StringFileInfo\"";
  print "  BEGIN";
  print "    BLOCK \"00000000\"";
  print "    BEGIN";
  print "      VALUE \"Comments\", \"This software consists of " \
        "voluntary contributions made by many individuals on behalf of " \
        "the Apache Software Foundation.  For more information on the " \
        "Apache Software Foundation, please see <http://www.apache.org/>\\0\"";
  print "      VALUE \"CompanyName\", \"Apache Software Foundation.\\0\"";
  print "      VALUE \"FileDescription\", \"" desc "\\0\"";
  print "      VALUE \"FileVersion\", \"" ver "\\0\"";
  print "      VALUE \"InternalName\", \"" file "\\0\"";
  print "      VALUE \"LegalCopyright\", \"Copyright (c) 2001, " \
        "The Apache Software Foundation.  Current License is available from " \
        "<http://www.apache.org/LICENSE.txt>\\0\"";
  print "      VALUE \"OriginalFilename\", \"" file ".exe\\0\"";
  if (vendor) {
    print "      VALUE \"PrivateBuild\", \"" vendor "\\0\"";
  }
  if (special) {
    print "      VALUE \"SpecialBuild\", \"" vendor "\\0\"";
  }
  print "      VALUE \"ProductName\", \"Apache httpd Server\\0\"";
  print "      VALUE \"ProductVersion\", \"" ver "\\0\"";
  print "    END";
  print "  END";
  print "  BLOCK \"VarFileInfo\"";
  print "  BEGIN";
  print "    VALUE \"Translation\", 0, 1200";
  print "  END";
  print "END";
}