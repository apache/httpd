#! /bin/sh

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#   This file is derived from the ant-1.5.3 distribution

#   +++ Changes for dedicated httpd documentation build +++
#
#   - ANT_HOME is the current directory (instead of parent)
#   - ignore external ANT_OPTS
#   - ignore external ANT_ARGS
#   - ignore external CLASSPATH
#   - set java stack size to 128 MB
#   - lower down verbosity (because the foreach task would be _very_ verbose
#     otherwise)
#

# explicit name our build file (may be replaced by a variable some time)
ANT_ARGS="-buildfile build.xml"

# lower down logger verbosity
ANT_ARGS="-logger org.apache.tools.ant.NoBannerLogger $ANT_ARGS"

# set regexp engine
ANT_ARGS="-Dant.regexp.regexpimpl=org.apache.tools.ant.util.regexp.JakartaOroRegexp $ANT_ARGS"

# raise heap/stack size...
ANT_OPTS="-Xmx128m -mx128m"

# set classpath
CLASSPATH=./lib

# set ant home directory (cwd)
ANT_HOME=.

# OS specific support.  $var _must_ be set to either true or false.
cygwin=false;
darwin=false;
case "`uname -a`" in
  CYGWIN*) cygwin=true ;;
  Darwin*) darwin=true
           if [ -z "$JAVA_HOME" ] ; then
             JAVA_HOME=/System/Library/Frameworks/JavaVM.framework/Home   
           fi
           ;;
  Linux*ppc*) ANT_OPTS="$ANT_OPTS -Xss1m -ss1m" ;;
esac

# For Cygwin, ensure paths are in UNIX format before anything is touched
if $cygwin ; then
  [ -n "$ANT_HOME" ] &&
    ANT_HOME=`cygpath --unix "$ANT_HOME"`
  [ -n "$JAVA_HOME" ] &&
    JAVA_HOME=`cygpath --unix "$JAVA_HOME"`
  [ -n "$CLASSPATH" ] &&
    CLASSPATH=`cygpath --path --unix "$CLASSPATH"`
fi

# set ANT_LIB location
ANT_LIB="${ANT_HOME}/lib"

if [ -z "$JAVACMD" ] ; then 
  if [ -n "$JAVA_HOME"  ] ; then
    if [ -x "$JAVA_HOME/jre/sh/java" ] ; then 
      # IBM's JDK on AIX uses strange locations for the executables
      JAVACMD="$JAVA_HOME/jre/sh/java"
    else
      JAVACMD="$JAVA_HOME/bin/java"
    fi
  else
    JAVACMD=`which java 2> /dev/null `
    if [ -z "$JAVACMD" ] ; then 
        JAVACMD=java
    fi
  fi
fi
 
if [ ! -x "$JAVACMD" ] ; then
  echo "Error: JAVA_HOME is not defined correctly."
  echo "  We cannot execute $JAVACMD"
  exit 1
fi

if [ -n "$CLASSPATH" ] ; then
  LOCALCLASSPATH="$CLASSPATH"
fi

# add in the dependency .jar files
for i in "${ANT_LIB}"/*.jar
do
  # if the directory is empty, then it will return the input string
  # this is stupid, so case for it
  if [ -f "$i" ] ; then
    if [ -z "$LOCALCLASSPATH" ] ; then
      LOCALCLASSPATH="$i"
    else
      LOCALCLASSPATH="$i":"$LOCALCLASSPATH"
    fi
  fi
done

if [ -n "$JAVA_HOME" ] ; then
  if [ -f "$JAVA_HOME/lib/tools.jar" ] ; then
    LOCALCLASSPATH="$LOCALCLASSPATH:$JAVA_HOME/lib/tools.jar"
  fi

  if [ -f "$JAVA_HOME/lib/classes.zip" ] ; then
    LOCALCLASSPATH="$LOCALCLASSPATH:$JAVA_HOME/lib/classes.zip"
  fi
else
  echo "Warning: JAVA_HOME environment variable is not set (or not exported)."
  echo "  If build fails because sun.* classes could not be found"
  echo "  you will need to set the JAVA_HOME environment variable"
  echo "  to the installation directory of java."
fi

# For Cygwin, switch paths to Windows format before running java
if $cygwin; then
  ANT_HOME=`cygpath --windows "$ANT_HOME"`
  JAVA_HOME=`cygpath --windows "$JAVA_HOME"`
  CLASSPATH=`cygpath --path --windows "$CLASSPATH"`
  LOCALCLASSPATH=`cygpath --path --windows "$LOCALCLASSPATH"`
  CYGHOME=`cygpath --windows "$HOME"`
fi

if [ -n "$CYGHOME" ]; then
    exec "$JAVACMD" $ANT_OPTS -Xbootclasspath/p:"$LOCALCLASSPATH" -classpath "$LOCALCLASSPATH" -Dant.home="${ANT_HOME}" -Dcygwin.user.home="$CYGHOME" org.apache.tools.ant.Main $ANT_ARGS "$@"
else
    exec "$JAVACMD" $ANT_OPTS -Xbootclasspath/p:"$LOCALCLASSPATH" -classpath "$LOCALCLASSPATH" -Dant.home="${ANT_HOME}" org.apache.tools.ant.Main $ANT_ARGS "$@"
fi

