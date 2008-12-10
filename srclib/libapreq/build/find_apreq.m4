dnl -------------------------------------------------------- -*- autoconf -*-
dnl Copyright 2002-2006 The Apache Software Foundation or its licensors, as
dnl applicable.
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl
dnl find_apu.m4 : locate the APR-util (APU) include files and libraries
dnl
dnl This macro file can be used by applications to find and use the APU
dnl library. It provides a standardized mechanism for using APU. It supports
dnl embedding APU into the application source, or locating an installed
dnl copy of APU.
dnl
dnl APR_FIND_APU(srcdir, builddir, implicit-install-check, acceptable-majors)
dnl
dnl   where srcdir is the location of the bundled APU source directory, or
dnl   empty if source is not bundled.
dnl
dnl   where builddir is the location where the bundled APU will be built,
dnl   or empty if the build will occur in the srcdir.
dnl
dnl   where implicit-install-check set to 1 indicates if there is no
dnl   --with-apr-util option specified, we will look for installed copies.
dnl
dnl   where acceptable-majors is a space separated list of acceptable major
dnl   version numbers. Often only a single major version will be acceptable.
dnl   If multiple versions are specified, and --with-apr-util=PREFIX or the
dnl   implicit installed search are used, then the first (leftmost) version
dnl   in the list that is found will be used.  Currently defaults to [0 1].
dnl
dnl Sets the following variables on exit:
dnl
dnl   apu_found : "yes", "no", "reconfig"
dnl
dnl   apu_config : If the apu-config tool exists, this refers to it.  If
dnl                apu_found is "reconfig", then the bundled directory
dnl                should be reconfigured *before* using apu_config.
dnl
dnl Note: this macro file assumes that apr-config has been installed; it
dnl       is normally considered a required part of an APR installation.
dnl
dnl Note: At this time, we cannot find *both* a source dir and a build dir.
dnl       If both are available, the build directory should be passed to
dnl       the --with-apr-util switch.
dnl
dnl Note: the installation layout is presumed to follow the standard
dnl       PREFIX/lib and PREFIX/include pattern. If the APU config file
dnl       is available (and can be found), then non-standard layouts are
dnl       possible, since it will be described in the config file.
dnl
dnl If a bundled source directory is available and needs to be (re)configured,
dnl then apu_found is set to "reconfig". The caller should reconfigure the
dnl (passed-in) source directory, placing the result in the build directory,
dnl as appropriate.
dnl
dnl If apu_found is "yes" or "reconfig", then the caller should use the
dnl value of apu_config to fetch any necessary build/link information.
dnl

AC_DEFUN([APR_FIND_APREQ], [
  apreq_found="no"

  if test "$target_os" = "os2-emx"; then
    # Scripts don't pass test -x on OS/2
    TEST_X="test -f"
  else
    TEST_X="test -x"
  fi

  ifelse([$4], [],
  [
    ifdef(AC_WARNING,([$0: missing argument 4 (acceptable-majors): Defaulting to APREQ 0.x then APREQ 1.x]))
    acceptable_majors="0 1"
  ], [acceptable_majors="$4"])

  apreq_temp_acceptable_apreq_config=""
  for apreq_temp_major in $acceptable_majors
  do
    case $apreq_temp_major in
      0)
      apreq_temp_acceptable_apreq_config="$apreq_temp_acceptable_apreq_config apreq-config"
      ;;
      *)
      apreq_temp_acceptable_apreq_config="$apreq_temp_acceptable_apreq_config apreq$apreq_temp_major-config"
      ;;
    esac
  done

  AC_MSG_CHECKING(for APREQ)
  AC_ARG_WITH(apreq,
  [  --with-apreq=PATH    prefix for installed APREQ, path to APREQ build tree,
                          or the full path to apreq-config],
  [
    if test "$withval" = "no" || test "$withval" = "yes"; then
      AC_MSG_ERROR([--with-apreq requires a directory or file to be provided])
    fi

    for apreq_temp_apreq_config_file in $apreq_temp_acceptable_apreq_config
    do
      for lookdir in "$withval/bin" "$withval"
      do
        if $TEST_X "$lookdir/$apreq_temp_apreq_config_file"; then
          apreq_found="yes"
          apreq_config="$lookdir/$apreq_temp_apreq_config_file"
          break 2
        fi
      done
    done

    if test "$apreq_found" != "yes" && $TEST_X "$withval" && $withval --help > /dev/null 2>&1 ; then
      apreq_found="yes"
      apreq_config="$withval"
    fi

    dnl if --with-apreq is used, it is a fatal error for its argument
    dnl to be invalid
    if test "$apreq_found" != "yes"; then
      AC_MSG_ERROR([the --with-apreq parameter is incorrect. It must specify an install prefix, a build directory, or an apreq-config file.])
    fi
  ],[
    if test -n "$3" && test "$3" = "1"; then
      for apreq_temp_apreq_config_file in $apreq_temp_acceptable_apreq_config
      do
        if $apreq_temp_apreq_config_file --help > /dev/null 2>&1 ; then
          apreq_found="yes"
          apreq_config="$apreq_temp_apreq_config_file"
          break
        else
          dnl look in some standard places (apparently not in builtin/default)
          for lookdir in /usr /usr/local /usr/local/apr /opt/apr /usr/local/apache2 ; do
            if $TEST_X "$lookdir/bin/$apreq_temp_apreq_config_file"; then
              apreq_found="yes"
              apreq_config="$lookdir/bin/$apreq_temp_apreq_config_file"
              break 2
            fi
          done
        fi
      done
    fi
    dnl if we have not found anything yet and have bundled source, use that
    if test "$apreq_found" = "no" && test -d "$1"; then
      apreq_temp_abs_srcdir="`cd $1 && pwd`"
      apreq_found="reconfig"
      apreq_bundled_major="`sed -n '/#define.*APREQ_MAJOR_VERSION/s/^[^0-9]*\([0-9]*\).*$/\1/p' \"$1/include/apreq_version.h\"`"
      case $apreq_bundled_major in
        "")
          AC_MSG_ERROR([failed to find major version of bundled APREQ])
        ;;
        0)
          apreq_temp_apreq_config_file="apreq-config"
        ;;
        *)
          apreq_temp_apreq_config_file="apreq$apreq_bundled_major-config"
        ;;
      esac
      if test -n "$2"; then
        apreq_config="$2/$apreq_temp_apreq_config_file"
      else
        apreq_config="$1/$apreq_temp_apreq_config_file"
      fi
    fi
  ])

  AC_MSG_RESULT($apreq_found)
])
