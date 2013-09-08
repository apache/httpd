Experimental cmake-based build support for Apache httpd on Microsoft Windows

Status
------

This build support is currently intended only for Microsoft Windows.

This build support is experimental.  Specifically,

* It does not support all features of Apache httpd.
* Some components may not be built correctly and/or in a manner
  compatible with the previous Windows build support.
* Build interfaces, such as the mechanisms which are used to enable
  optional functionality or specify prerequisites, may change from
  release to release as feedback is received from users and bugs and
  limitations are resolved.

This can be used with Apache httpd 2.4.x by copying the following files from
httpd trunk (in Subversion) into the 2.4.x source tree:

* CMakeLists.txt
* build/cpR_noreplace.pl

Important: Refer to the "Known Bugs and Limitations" section for further
           information.

           It is beyond the scope of this document to document or explain
           how to utilize the various cmake features, such as different
           build backends or provisions for finding support libraries.

           Please refer to the cmake documentation for additional information
           that applies to building any project with cmake.

Prerequisites
-------------

The following tools must be in PATH:

* cmake, version 2.8 or later
* Perl
* If the WITH_MODULES feature is used: awk
* If using a command-line compiler: compiler and linker and related tools
  (Refer to the cmake documentation for more information.)

The following support libraries are mandatory:

* APR, built with cmake
  + Either APR 2.0-dev (trunk) or APR 1.4.x and APR-Util 1.5.x.
  + When building APR (but not APR-Util 1.5.x), specify the build option
    APR_INSTALL_PRIVATE_H so that non-standard files required for building
    Apache httpd are installed.
  + Additional APR settings affect httpd but are not mandatory, such as
    APR_HAVE_IPV6.
* PCRE

Additional support libraries allow optional features of httpd to be enabled:

* libxml2 (e.g., mod_proxy_html)
* openssl (e.g., mod_ssl)
* zlib (e.g., mod_deflate)

How to build
------------

1. cd to a clean directory for building (i.e., don't build in your
   source tree)

2. Make sure Perl is in your PATH.  Additionally, some backends may want
   your compile tools in PATH.  (Hint: "Visual Studio Command Prompt")
   In the unlikely event that you use -DWITH_MODULES, make sure awk is
   in PATH.

3. cmake -G "some backend, like 'NMake Makefiles'"
     -DCMAKE_INSTALL_PREFIX=d:/path/to/httpdinst
     -DENABLE_foo=A|I|O|a|i
     d:/path/to/httpdsource

   Alternately, you can use the cmake-gui and update settings in the GUI.

   PCRE_INCLUDE_DIR, PCRE_LIBRARIES, APR_INCLUDE_DIR, APR_LIBRARIES:

       cmake doesn't bundle FindXXX for these packages, so the crucial
       information has to be specified in this manner if they aren't found
       in their default location.

     -DPCRE_INCLUDE_DIR=d:/path/to/pcreinst/include
     -DPCRE_LIBRARIES=d:/path/to/pcreinst/lib/pcre[d].lib

       These will have to be specified only if PCRE is installed to a different
       directory than httpd, or if debug *and* release builds of PCRE were
       installed there and you want to control which is used.  (Currently the
       build will use pcred.lib (debug) if it is found in the default location
       and not overridden with -DPCRE_LIBRARIES.)

     -DAPR_INCLUDE_DIR=d:/path/to/aprinst/include
     -DAPR_LIBRARIES="d:/path/to/aprinst/lib/libapr-1.lib;d:/path/to/aprinst/lib/libaprutil-1.lib"

       These will have to be specified if APR[-Util] was installed to a
       different directory than httpd.

       When building with APR trunk (future APR 2.x, with integrated APR-Util),
       specify just the path to libapr-2.lib:

           -DAPR_LIBRARIES=d:/path/to/aprinst/lib/libapr-2.lib

       APR+APR-Util 1.x vs. APR trunk will be detected automatically if they
       are installed to the same location as httpd.

   LIBXML2_ICONV_INCLUDE_DIR, LIBXML2_ICONV_LIBRARIES

      If using a module that requires libxml2 and the build of libxml2 requires
      iconv, set these variables to allow iconv includes and libraries to be
      used.  For example:

      -DLIBXML2_ICONV_INCLUDE_DIR=c:\iconv-1.9.2.win32\include
      -DLIBXML2_ICONV_LIBRARIES=c:\iconv-1.9.2.win32\lib\iconv.lib

   CMAKE_C_FLAGS_RELEASE, _DEBUG, _RELWITHDEBINFO, _MINSIZEREL
   CMAKE_BUILD_TYPE
       For NMake Makefiles the choices are at least DEBUG, RELEASE,
       RELWITHDEBINFO, and MINSIZEREL
       Other backends make have other selections.

   ENABLE_foo:
       Each module has a default setting which can be overridden with one of
       the following values:
           A        build and Activate module
           a        build and Activate module IFF prereqs are available; if
                    prereqs are unavailable, don't build it
           I        build module but leave it Inactive (commented-out
                    LoadModule directive)
           i        build module but leave it Inactive IFF prereqs are
                    available; if prereqs are unavailable, don't build it
           O        Omit module completely

       Examples: -DENABLE_ACCESS_COMPAT=O
                 -DENABLE_PROXY_HTML=i

   WITH_MODULES:
       Comma-separated paths to single file modules to statically link into
       the server, like the --with-module=modpath:/path/to/mod_foo.c with
       the autoconf-based build.  Key differences: The modpath (e.g., 
       "generators") isn't provided or used, and the copy of the module
       source being built is automatically updated when it changes.
       See also EXTRA_INCLUDE_DIRS.

   EXTRA_INCLUDE_DIRS:
       List of additional directories to search for .h files.  This may
       be necessary when including third-party modules in the httpd build
       via WITH_MODULES.

   Port and SSLPort: port numbers for substitution into default .conf files.
   (The defaults are 80 and 443.)

4. build using chosen backend (e.g., "nmake install")

Running the server and support programs
---------------------------------------

This build system does not copy binaries such as dlls from other projects
into the httpd install location.  Without taking some precautions, httpd
and support programs can fail to start or modules can fail to load because
a support library can't be found in PATH or in the directory of the httpd
binary.

This can be resolved in several different ways:

* Install httpd and the various support libraries to a common install
  prefix so that support libraries and httpd programs are installed in
  the same bin directory and are found without setting PATH.

* Update PATH to include the bin directories of all necessary support
  libraries.

  Depending on where PATH is set, it may not affect starting httpd as
  a service.

* Maintain a script which combines required binaries into a common 
  location, such as the httpd installion bin directory, and use that
  script after building or otherwise installing or updating support
  libraries.

* AVOID THE USE of any unrepeatable process of copying dll files around
  from different install locations until something starts working.  The
  result is that when you later update a support library to pick up a
  security fix, httpd will likely continue to use the old, vulnerable
  library file.

Known Bugs and Limitations
--------------------------

* no standard script or makefile is provided to tie together the builds
  of httpd and support libraries in a manner suitable for typical users
* no logic to find support libraries or otherwise build these modules:
  + mod_socache_dc (distcache), mod_serf (serf)
  + additionally, mod_lbmethod_rr and mod_firehose don't compile on Windows
    anyway
* buildmark.c isn't necessarily rebuilt when httpd.exe is regenerated
* ApacheMonitor has a build error and is disabled
* CGI examples aren't installed
* dbmmanage.pl, httxt2dbm, wintty aren't built/installed
* mod_dav.lib and anything else isn't installed, nor are any .exp files (though
  I don't know what would use them)
* module enablement defaults are not in sync with the autoconf-based build
* no support for static PCRE builds (need to detect then turn on PCRE_STATIC)
* module base addresses aren't set

Generally:

* Many httpd features have not been tested with this build.
* Developers need to examine the existing Windows build in great detail and see
  what is missing from the cmake-based build, whether a feature or some build
  nuance.
* Any feedback you can provide on your experiences with this build will be
  helpful.
