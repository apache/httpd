#!/bin/sh
#
# binbuild.sh - Builds an Apache binary distribution.
# Initially written by Lars Eilebrecht <lars@apache.org>.
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE


APDIR=$(basename $(pwd))
VER=$(echo $APDIR |sed s/apache-//)
OS=$(src/helpers/GuessOS)
USER="$(src/helpers/buildinfo.sh -n %u@%h%d)"
TAR="$(src/helpers/findprg.sh tar)"
GTAR="$(src/helpers/findprg.sh gtar)"
GZIP="$(src/helpers/findprg.sh gzip)"
CONFIGPARAM="--with-layout=BinaryDistribution --enable-module=most --enable-shared=max"

if [ ! -f ./ABOUT_APACHE ]
then
  echo "ERROR: The current directory contains no valid Apache distribution."
  echo "Please change the directory to the top level directory of a freshly"
  echo "unpacked Apache 1.3 source distribution and re-execute the script"
  echo "'./src/helpers/bindbuild.sh'." 
  exit 1;
fi

if [ -d ./CVS ]
then
  echo "ERROR: The current directory is a CVS checkout of Apache."
  echo "Only a standard Apache 1.3 source distribution should be used to"
  echo "create a binary distribution."
  exit 1;
fi

echo "Building Apache $VER binary distribution..."
echo "Platform is \"$OS\"..."

( echo "Build log for Apache binary distribution" && \
  echo "----------------------------------------------------------------------" && \
  ./configure $CONFIGPARAM && \
  echo "----------------------------------------------------------------------" && \
  make clean && \
  rm -rf bindist install-bindist.sh *.bindist
  echo "----------------------------------------------------------------------" && \
  make && \
  echo "----------------------------------------------------------------------" && \
  make install-quiet root="bindist/" && \
  echo "----------------------------------------------------------------------" && \
  make clean && \
  echo "----------------------------------------------------------------------" && \
  echo "[EOF]" \
) > build.log 2>&1

if [ ! -f ./bindist/bin/httpd ]
then
  echo "ERROR: Failed to build Apache. See \"build.log\" for details."
  exit 1;
fi

echo "Binary images successfully created..."
echo "Creating supplementary files..."

( echo " " && \
  echo "Apache $VER binary distribution" && \
  echo "================================" && \
  echo " " && \
  echo "This binary distribution is usable on a \"$OS\"" && \
  echo "system and was built by \"$USER\"." && \
  echo "" && \
  echo "The distribution contains all standard Apache modules as shared" && \
  echo "objects. This allows you to enable or disable particular modules" && \
  echo "with the LoadModule/AddModule directives in the configuration file" && \
  echo "without the need to re-compile Apache." && \
  echo "" && \
  echo "See \"INSTALL.bindist\" on how to install the distribution." && \
  echo " " && \
  echo "NOTE: Please do not send support-related mails to the address mentioned" && \
  echo "      above or to any member of the Apache Group! Support questions" && \
  echo "      should be directed to the \"comp.infosystems.www.servers.unix\"" && \
  echo "      or \"comp.infosystems.www.servers.ms-windows\" newsgroup" && \
  echo "      (as appropriate for the platform you use), where some of the" && \
  echo "      Apache team lurk, in the company of many other Apache gurus" && \
  echo "      who should be able to help." && \
  echo "      If you think you found a bug in Apache or have a suggestion please" && \
  echo "      visit the bug report page at http://www.apache.org/bug_report.html" && \
  echo " " && \
  echo "----------------------------------------------------------------------" && \
  ./bindist/bin/httpd -V && \
  echo "----------------------------------------------------------------------" \
) > README.bindist
cp README.bindist ../apache-$VER-$OS.README

( echo " " && \
  echo "Apache $VER binary installation" && \
  echo "================================" && \
  echo " " && \
  echo "To install this binary distribution you have to execute the installation" && \
  echo "script \"install-bindist.sh\" in the top-level directory of the distribution." && \
  echo " " && \
  echo "The script takes the ServerRoot directory into which you want to install" && \
  echo "Apache as an option. If you ommit the option the default path" && \
  echo "\"/usr/local/apache\" is used." && \
  echo "Make sure you have write permissions in the target directory, e.g. switch" && \
  echo "to user \"root\" before you execute the script." && \
  echo " " && \
  echo "See \"README.bindist\" for further details about this distribution." && \
  echo " " && \
  echo "Please note that this distribution includes the complete Apache source code." && \
  echo "Therefore you may compile Apache yourself at any time if you have a compiler" && \
  echo "installation on your system." && \
  echo "See \"INSTALL\" for details on how to accomplish this." && \
  echo " " \
) > INSTALL.bindist

( echo "#!/bin/sh" && \
  echo "#" && \
  echo "# Usage: install-bindist.sh [ServerRoot]" && \
  echo "# This script installs the Apache binary distribution and" && \
  echo "# was automatically created by binbuild.sh." && \
  echo " " && \
  echo "if [ .\$1 = . ]" && \
  echo "then" && \
  echo "  SR=/usr/local/apache" && \
  echo "else" && \
  echo "  SR=\$1" && \
  echo "fi" && \
  echo "echo \"Installing binary distribution for platform $OS\"" && \
  echo "echo \"into directory \$SR ...\"" && \
  echo "./src/helpers/mkdir.sh \$SR" && \
  echo "cp -r bindist/proxy \$SR/proxy" && \
  echo "cp -r bindist/man \$SR/man" && \
  echo "cp -r bindist/logs \$SR/logs" && \
  echo "cp -r bindist/libexec \$SR/libexec" && \
  echo "cp -r bindist/include \$SR/include" && \
  echo "cp -r bindist/icons \$SR/icons" && \
  echo "cp -r bindist/cgi-bin \$SR/cgi-bin" && \
  echo "cp -r bindist/bin \$SR/bin" && \
  echo "if [ -d \$SR/conf ]" && \
  echo "then" && \
  echo "  echo \"[Preserving existing configuration files.]\"" && \
  echo "  cp -r bindist/conf/*.default \$SR/conf/" && \
  echo "else" && \
  echo "  cp -r bindist/conf \$SR/conf" && \
  echo "fi" && \
  echo "if [ -d \$SR/htdocs ]" && \
  echo "then" && \
  echo "  echo \"[Preserving existing htdocs directory.]\"" && \
  echo "else" && \
  echo "  cp -r bindist/htdocs \$SR/htdocs" && \
  echo "fi" && \
  echo "sed -e s%/usr/local/apache%\$SR/% \$SR/conf/httpd.conf.default > \$SR/conf/httpd.conf" && \
  echo "sed -e s%PIDFILE=%PIDFILE=\$SR/% -e s%HTTPD=%HTTPD=\\\"\$SR/% -e \"s%/httpd$%/httpd -d \$SR\\\"%\" bindist/bin/apachectl > \$SR/bin/apachectl" && \
  echo " " && \
  echo "echo \"Ready.\"" && \
  echo "echo \" +--------------------------------------------------------+\"" && \
  echo "echo \" | You now have successfully installed the Apache $VER   |\"" && \
  echo "echo \" | HTTP server. To verify that Apache actually works      |\"" && \
  echo "echo \" | correctly you now should first check the (initially    |\"" && \
  echo "echo \" | created or preserved) configuration files              |\"" && \
  echo "echo \" |                                                        |\"" && \
  echo "echo \" |   \$SR/conf/httpd.conf\"" && \
  echo "echo \" |                                                        |\"" && \
  echo "echo \" | and then you should be able to immediately fire up     |\"" && \
  echo "echo \" | Apache the first time by running:                      |\"" && \
  echo "echo \" |                                                        |\"" && \
  echo "echo \" |   \$SR/bin/apachectl start \"" &&\
  echo "echo \" |                                                        |\"" && \
  echo "echo \" | Thanks for using Apache.       The Apache Group        |\"" && \
  echo "echo \" |                                http://www.apache.org/  |\"" && \
  echo "echo \" +--------------------------------------------------------+\"" && \
  echo "echo \" \"" \
) > install-bindist.sh
chmod 755 install-bindist.sh

sed -e "s%\"/htdocs%\"/usr/local/apache/htdocs%" \
    -e "s%\"/icons%\"/usr/local/apache/icons%" \
    -e "s%\"/cgi-bin%\"/usr/local/apache/cgi-bin%" \
    -e "s%^ServerAdmin.*%ServerAdmin you@your.address%" \
    -e "s%#ServerName.*%#ServerName localhost%" \
    -e "s%Port 8080%Port 80%" \
    bindist/conf/httpd.conf.default > bindist/conf/httpd.conf
cp bindist/conf/httpd.conf bindist/conf/httpd.conf.default

echo "Creating distribution archive and readme file..."
 
if [ ".`grep -i error build.log > /dev/null`" != . ]
then
  echo "ERROR: Failed to build Apache. See \"build.log\" for details."
  exit 1;
else
  if [ ".$GTAR" != . ]
  then
    $GTAR -zcf ../apache-$VER-$OS.tar.gz -C .. --owner=root --group=root apache-$VER
  else
    if [ ".$TAR" != . ]
    then
      $TAR -cf ../apache-$VER-$OS.tar -C .. apache-$VER
      if [ ".$GZIP" != . ]
      then
        $GZIP ../apache-$VER-$OS.tar
      fi
    else
      echo "ERROR: Could not find a 'tar' program!"
      echo "       Please execute the following commands manually:"
      echo "         tar -cf ../apache-$VER-$OS.tar ."
      echo "         gzip ../apache-$VER-$OS.tar"
    fi
  fi

  if [ -f ../apache-$VER-$OS.tar.gz ] && [ -f ../apache-$VER-$OS.README ]
  then
    echo "Ready."
    echo "You can find the binary archive (apache-$VER-$OS.tar.gz)"
    echo "and the readme file (apache-$VER-$OS.README) in the"
    echo "parent directory."
    exit 0;
  else
    exit 1;
  fi
fi
