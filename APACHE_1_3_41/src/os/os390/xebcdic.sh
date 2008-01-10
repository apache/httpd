#!/bin/sh
#
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
#
#
# xebcdic.sh fileName [--all-ascii-content] [--f=pattern ... ]
#
# This shell script decompresses an archive containing an apache source tree
# and then extracts the source files from the archive.  The source files are
# translated from ASCII to EBCDIC as they are extracted from the archive.
# Once all the files have been extracted and translated, the binary files are
# re-extracted to undo the ASCII to EBCDIC translation on those files.  Once
# this script is done, the extracted tree can be used on an EBCDIC based
# system.
#
# Input:  fileName -- fileName has one of the following formats:
#                     apache-version_timeStamp.tar.gz or
#                     apache-version_timeStamp.tar.Z  or
#                     apache-version.tar.gz           or
#                     apache-version.tar.Z            or
#                     apache_version.tar.gz           or
#                     apache_version.tar.Z
#
#          --f=pattern -- specifies that all files which match the pattern
#                         are to be re-extracted without ascii to ebcdic
#                         translation being applied.  pattern is a file name
#                         specification that may contain path names and
#                         the wildcard character.  All paths are assumed to
#                         be under the apache source tree top.  Binary files
#                         are always re-extracted without ascii to ebcdic
#                         translation regardless of whether any pattern is
#                         specified or not.  Multiple patterns may be specified
#                         by repeating this option.
#
#
#          --all-ascii-content -- specifies that all the text content shipped
#                                 with the apache tree should be stored in
#                                 ascii on the OS/390 system. This re-extracts
#                                 all the *.htm* files in the htdocs directory
#                                 of the apache tree without doing the ascii
#                                 to ebcdic translation.  In addition to the
#                                 *.htm* files, file htdocs/manual/LICENSE and
#                                 file htdocs/manual/misc/HTTP_Features.tsv
#                                 are also stored in ascii.  If this option
#                                 is specified, directives AddType and
#                                 DefaultType need to be used to correctly
#                                 serve the pages without trying to first
#                                 translate from ebcdic to ascii.  See
#                                 apache-tree-top/src/README.EBCDIC.
#
# Example Invocations:
#
#          ./xebcdic.sh apache_1.3.9.tar.gz:  Runs gunzip, runs pax and
#               extracts everything translating it to ebcdic, and re-extracts
#               all gif files in the htdocs and icons directories without
#               applying ascii to ebcdic translation.
#
#          ./xebcdic.sh apache_1.3.9.tar.gz --f=*.htm* --f=htdocs/*.tsv:
#               Runs gunzip, runs pax and extracts everything translating it to
#               ebcdic, re-extracts all gif files without ascii to ebcdic
#               translation, and re-extracts all the *.htm* files in the apache
#               source tree and all *.tsv files in the htdocs directory of the
#               apache source tree without ascii to ebcdic translation.
#
#          ./xebcdic.sh apache_1.3.9.tar.gz --all-ascii-content:  Runs gunzip,
#               runs pax and extracts everything translating it to ebcdic,
#               re-extracts all gif files without ascii to ebcdic translation,
#               and re-extracts all the *.htm* files in the htdocs directory
#               as well as htdocs/manual/LICENSE and
#               htdocs/manual/misc/HTTP_Features.tsv without ascii to ebcdic
#               translation.
#
# Output:  fileName.tar.gz is replaced with fileName.tar and the apache
#          source tree is extracted into a directory named apache-version or
#          apache_version.  All files except binary files and any files
#          specified through the options are translated from ascii to
#          ebcdic.
#
# Assumptions:  The path to gunzip, uncompress and pax is defined and
#               from where this script is invoked.
#

echo "Input file name is:  $1"

# Verify fileName
if ! echo $1 | grep -q 'apache_.*\.tar\.gz' && \
   ! echo $1 | grep -q 'apache_.*\.tar\.Z'  && \
   ! echo $1 | grep -q 'apache-.*_.*\.tar\.gz' && \
   ! echo $1 | grep -q 'apache-.*_.*\.tar\.Z' && \
   ! echo $1 | grep -q 'apache-.*\.tar\.gz' && \
   ! echo $1 | grep -q 'apache-.*\.tar\.Z'
then
  echo "Filename, $1, does not follow required format."
  echo "Filename should have one of the following formats:"
  echo "apache-version_timeStamp.tar.gz or"
  echo "apache-version_timeStamp.tar.Z  or"
  echo "apache-version.tar.gz           or"
  echo "apache-version.tar.Z            or"
  echo "apache_version.tar.gz           or"
  echo "apache_version.tar.Z"
  exit 1;
fi

if [ ! -f $1 ]; then
  echo "$1 is not a file"
  exit 1;
fi

if [ ! -a $1 ]; then
  echo "$1 file does not exist"
  exit 1;
fi

# Verify fileType option if specified
for option in $@
do
  case "$option" in
                      $1) ;;
     --all-ascii-content) ;;	
                   --f=*) ;;
	               *) echo "Invalid option specified.  Command syntax is:"
	                  echo "xebcdic.sh compressed-archive-file-name [--all-ascii-content]"
			  echo "                                        [--f=pattern ... ]"
                          exit 1;
      	                  ;;
  esac
done

# Figure out whether to gunzip or uncompress
if echo $1 | grep -q 'apache[-_].*\.tar\.gz'; then
  DECOMPRESS="gunzip"
else
  DECOMPRESS="uncompress"
fi
echo "Decompression utility $DECOMPRESS will be used."

# Set name of tar file after decompressing
if [ "x$DECOMPRESS" = "xgunzip" ]; then
  TARFILE=`echo $1 | sed s/\.tar\.gz/\.tar/`
else
  TARFILE=`echo $1 | sed s/\.tar\.Z/\.tar/`
fi
echo "Archive file name is: $TARFILE"

# Set name of apache source tree directory
if echo $1 | grep -q 'apache-.*_.*\.tar*'; then
  APDIR=`echo $1 | sed s/_.*//`
else
  APDIR=`echo $1 | sed s/\.tar.*//`
fi
echo "Apache source tree top is: $APDIR"

# Decompress input file
echo "Starting decompression of $1"
if [ "x$DECOMPRESS" = "xgunzip" ]; then
  if gunzip $1; then
    echo "Decompression of $1 completed successfully"
  else
    exit 1;
  fi
else
  if uncompress $1; then
    echo "Decompression of $1 completed successfully"
  else
    exit 1;
  fi
fi

# Extract source files and translate them all from ASCII to EBCDIC

# Determine code page for locale

echo "Starting extraction of source files from archive $TARFILE."
echo "ASCII being translated to EBCDIC."
echo "ASCII code page assumed to be ISO8859-1."
echo "EBCDIC code page assumed to be IBM-1047."
pax -ofrom=ISO8859-1,to=IBM-1047 -rvf $TARFILE
echo "Extraction and translation of source files from archive completed."

# Re-extract gif files without ASCII to EBCDIC translation
echo "Re-extracting gif files without ASCII to EBCDIC translation"
pax -rvf $TARFILE $(find $APDIR/htdocs -type f -name "*.gif*")
pax -rvf $TARFILE $(find $APDIR/icons -type f -name "*.gif*")

# Re-extract appropriate files as requested by user
for option in $@; do
  case "$option" in
		      $1)
			  ;;
     --all-ascii-content) echo "Re-extracting files in $APDIR/htdocs without ASCII to EBCDIC translation"
			  pax -rvf $TARFILE $(find $APDIR/htdocs -type f -name "*.htm*")
			  pax -rvf $TARFILE $(find $APDIR/htdocs -type f -name "*.tsv*")
			  pax -rvf $TARFILE $(find $APDIR/htdocs -name "manual/LICENSE")
			  ;;
		   --f=*) PATTERN=`echo $option | sed s/--f=//`
			  if [ "x$PATTERN" != "x" ]; then
			    echo "Re-extracting files matching $PATTERN without ASCII to EBCDIC translation"
			    pax -rvf $TARFILE $(find $APDIR -type f -name "$PATTERN")
			  fi
			  ;;
		       *)
			  ;;
  esac
done

