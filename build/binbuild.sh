#!/bin/sh
#
# binbuild.sh - Builds an Apache binary distribution.
# Initially written by Lars Eilebrecht <lars@apache.org>.
#
# This script falls under the Apache License.
# See http://www.apache.org/docs/LICENSE

OS=`src/helpers/GuessOS`
case "x$OS" in
  x*390*) CONFIGPARAM="--with-layout=BinaryDistribution --enable-module=most";;
      *) CONFIGPARAM="--with-layout=BinaryDistribution --enable-module=most --enable-shared=max";;
esac
APDIR=`pwd`
APDIR=`basename $APDIR`
VER=`echo $APDIR |sed s/apache_//`
TAR="`src/helpers/PrintPath tar`"
GTAR="`src/helpers/PrintPath gtar`"
GZIP="`src/helpers/PrintPath gzip`"

if [ x$1 != x ]
then
  USER=$1
else
  USER="`src/helpers/buildinfo.sh -n %u@%h%d`"
fi

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

echo "Binary image successfully created..."

./bindist/bin/httpd -v

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
cp README.bindist ../apache_$VER-$OS.README

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
  echo "lmkdir()" && \
  echo "{" && \
  echo "  path=\"\"" && \
  echo "  dirs=\`echo \$1 | sed -e 's%/% %g'\`" && \
  echo "  mode=\$2" && \
  echo " " && \
  echo "  set -- \${dirs}" && \
  echo " " && \
  echo "  for d in \${dirs}" && \
  echo "  do" && \
  echo "    path=\"\${path}/\$d\"" && \
  echo "    if test ! -d \"\${path}\" ; then" && \
  echo "      mkdir \${path}" && \
  echo "      if test \$? -ne 0 ; then" && \
  echo "        echo \"Failed to create directory: \${path}\"" && \
  echo "        exit 1" && \
  echo "      fi" && \
  echo "      chmod \${mode} \${path}" && \
  echo "    fi" && \
  echo "  done" && \
  echo "}" && \
  echo " " && \
  echo "lcopy()" && \
  echo "{" && \
  echo "  from=\$1" && \
  echo "  to=\$2" && \
  echo "  dmode=\$3" && \
  echo "  fmode=\$4" && \
  echo " " && \
  echo "  test -d \${to} || lmkdir \${to} \${dmode}" && \
  echo "  (cd \${from} && tar -cf - *) | (cd \${to} && tar -xf -)" && \
  echo " " && \
  echo "  if test \"X\${fmode}\" != X ; then" && \
  echo "    find \${to} -type f -print | xargs chmod \${fmode}" && \
  echo "  fi" && \
  echo "  if test \"X\${dmode}\" != X ; then" && \
  echo "    find \${to} -type d -print | xargs chmod \${dmode}" && \
  echo "  fi" && \
  echo "}" && \
  echo " " && \
  echo "##" && \
  echo "##  determine path to (optional) Perl interpreter" && \
  echo "##" && \
  echo "PERL=no-perl5-on-this-system" && \
  echo "perls='perl5 perl'" && \
  echo "path=\`echo \$PATH | sed -e 's/:/ /g'\`" && \
  echo " " && \
  echo "for dir in \${path} ;  do" && \
  echo "  for pperl in \${perls} ; do" && \
  echo "    if test -f \"\${dir}/\${pperl}\" ; then" && \
  echo "      if \`\${dir}/\${pperl} -v | grep 'version 5\.' >/dev/null 2>&1\` ; then" && \
  echo "        PERL=\"\${dir}/\${pperl}\"" && \
  echo "        break" && \
  echo "      fi" && \
  echo "    fi" && \
  echo "  done" && \
  echo "done" && \
  echo " " && \
  echo "if [ .\$1 = . ]" && \
  echo "then" && \
  echo "  SR=/usr/local/apache" && \
  echo "else" && \
  echo "  SR=\$1" && \
  echo "fi" && \
  echo "echo \"Installing binary distribution for platform $OS\"" && \
  echo "echo \"into directory \$SR ...\"" && \
  echo "lmkdir \$SR 755" && \
  echo "lmkdir \$SR/proxy 750" && \
  echo "lmkdir \$SR/logs 750" && \
  echo "lcopy bindist/man \$SR/man 755 644" && \
  echo "lcopy bindist/libexec \$SR/libexec 750 644" && \
  echo "lcopy bindist/include \$SR/include 755 644" && \
  echo "lcopy bindist/icons \$SR/icons 755 644" && \
  echo "lcopy bindist/cgi-bin \$SR/cgi-bin 750 750" && \
  echo "lcopy bindist/bin \$SR/bin 750 750" && \
  echo "if [ -d \$SR/conf ]" && \
  echo "then" && \
  echo "  echo \"[Preserving existing configuration files.]\"" && \
  echo "  cp bindist/conf/*.default \$SR/conf/" && \
  echo "else" && \
  echo "  lcopy bindist/conf \$SR/conf 750 640" && \
  echo "fi" && \
  echo "if [ -d \$SR/htdocs ]" && \
  echo "then" && \
  echo "  echo \"[Preserving existing htdocs directory.]\"" && \
  echo "else" && \
  echo "  lcopy bindist/htdocs \$SR/htdocs 755 644" && \
  echo "fi" && \
  echo " " && \
  echo "sed -e \"s;^#!/.*;#!\$PERL;\" -e \"s;\@prefix\@;\$SR;\" -e \"s;\@sbindir\@;\$SR/bin;\" \\" && \
  echo "	-e \"s;\@libexecdir\@;\$SR/libexec;\" -e \"s;\@includedir\@;\$SR/include;\" \\" && \
  echo "	-e \"s;\@sysconfdir\@;\$SR/conf;\" bindist/bin/apxs > \$SR/bin/apxs" && \
  echo "sed -e \"s;^#!/.*;#!\$PERL;\" bindist/bin/dbmmanage > \$SR/bin/dbmmanage" && \
  echo "sed -e \"s%/usr/local/apache%\$SR%\" \$SR/conf/httpd.conf.default > \$SR/conf/httpd.conf" && \
  echo "sed -e \"s%PIDFILE=%PIDFILE=\$SR/%\" -e \"s%HTTPD=%HTTPD=\\\"\$SR/%\" -e \"s%httpd\$%httpd -d \$SR -R \$SR/libexec\\\"%\" bindist/bin/apachectl > \$SR/bin/apachectl" && \
  echo " " && \
  echo "echo \"Ready.\"" && \
  echo "echo \" +--------------------------------------------------------+\"" && \
  echo "echo \" | You now have successfully installed the Apache $VER   |\"" && \
  echo "echo \" | HTTP server. To verify that Apache actually works      |\"" && \
  echo "echo \" | correctly you should first check the (initially        |\"" && \
  echo "echo \" | created or preserved) configuration files:             |\"" && \
  echo "echo \" |                                                        |\"" && \
  echo "echo \" |   \$SR/conf/httpd.conf\"" && \
  echo "echo \" |                                                        |\"" && \
  echo "echo \" | You should then be able to immediately fire up         |\"" && \
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

sed -e "s%\"htdocs%\"/usr/local/apache/htdocs%" \
    -e "s%\"icons%\"/usr/local/apache/icons%" \
    -e "s%\"cgi-bin%\"/usr/local/apache/cgi-bin%" \
    -e "s%\"proxy%\"/usr/local/apache/proxy%" \
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
  if [ "x$GTAR" != "x" ]
  then
    $GTAR -zcf ../apache_$VER-$OS.tar.gz -C .. apache_$VER
  else
    if [ "x$TAR" != "x" ]
    then
      case "x$OS" in
        x*390*) $TAR -cfU ../apache_$VER-$OS.tar -C .. apache_$VER;;
	    *) $TAR -cf ../apache_$VER-$OS.tar -C .. apache_$VER;;
      esac
      if [ "x$GZIP" != "x" ]
      then
        $GZIP ../apache_$VER-$OS.tar
      fi
    else
      echo "ERROR: Could not find a 'tar' program!"
      echo "       Please execute the following commands manually:"
      echo "         tar -cf ../apache_$VER-$OS.tar ."
      echo "         gzip ../apache_$VER-$OS.tar"
    fi
  fi

  if [ -f ../apache_$VER-$OS.tar.gz ] && [ -f ../apache_$VER-$OS.README ]
  then
    echo "Ready."
    echo "You can find the binary archive (apache_$VER-$OS.tar.gz)"
    echo "and the readme file (apache_$VER-$OS.README) in the"
    echo "parent directory."
    exit 0;
  else
    exit 1;
  fi
fi
