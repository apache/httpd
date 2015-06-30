#!/bin/sh
# Copyright 2015 greenbytes GmbH (https://www.greenbytes.de)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SYSCONF="$1"
DESTDIR="$2"
A2ENMOD="$( type -p a2enmod )"

INSTALL_LOC=""

if [ -d "$DESTDIR" ]; then
    INSTALL_LOC="$DESTDIR/$SYSCONF"
else
    INSTALL_LOC="$SYSCONF"
fi
echo "[DEBUG] Install location is assumed to be $INSTALL_LOC"
if [ -d "$SYSCONF/mods-available" ]; then
    echo -n "Debian layout assumed, installing mod_h2 config in $INSTALL_LOC..."
    cp h2.conf h2.load "$INSTALL_LOC/mods-available"
    echo "done."
    if [ -x "$A2ENMOD" ] && [ ! -d "$DESTDIR" ]; then
        echo -n "enabling mod_h2..."
        "$A2ENMOD" mod_h2
        echo "done."
    fi
elif [ -d "$SYSCONF/../conf.d" ] && [ -d "$SYSCONF/../conf.modules.d" ]; then
    # Odds are this is a Fedora box!
    echo -n "RHEL/Fedora layout assumed, installing mod_h2 config in $INSTALL_LOC..."
    cp h2.conf "$INSTALL_LOC/../conf.d"
    cp h2.load "$INSTALL_LOC/../conf.modules.d/10-h2.conf"
    echo "done."
else
    cat <<EOF
  This does not look like a apache2 installation, as in Ubuntu or
  other debian based systems. Therefore, the local files h2.load and
  h2.conf have *not* been installed.

  If you want to have the h2 module enabled in your apache installtion, you
  need to add
     LoadModule h2_module modules/mod_h2.so
  somewhere in your config files and add a line like
     H2Engine on
  whereever you want the module to be active (general server of specific
  virtual hosts).

EOF
fi

