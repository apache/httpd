#!perl -w
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
# This script is intended to be called from within the docs build process.
# It gets no parameters.
# It assumes, that the current working directory is the root of the manual.

# The script doesn't use an XML parser (yet?) so care should be taken with
# non-ascii characters.

# TODO:
# - rewrite in java as ant task?

# against fat fingers
use strict;

# for file operations
use FindBin;
use lib $FindBin::Bin;
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_TRUNC);
use DocUtil qw(docpath $ignore_files);

# Scratch stuff
my ($ext, $curpath, @mod_files, @suffix);

# get available languages automatically:
# (a) we find out which languages the sitemap provides
# (b) we find out which languages the module files provide
$curpath = docpath();
opendir(DIR, $curpath)
    or die "could not open directory '$curpath' ($!), stopped";

@suffix = map { s/^sitemap\.xml//; $_ }
       grep !/$ignore_files/
    => grep  /^sitemap\.xml/
    => readdir(DIR);

closedir(DIR)
    or die "could not close directory '$curpath' ($!), stopped";

# (b)
$curpath = docpath('mod');
opendir(DIR, $curpath)
    or die "could not open directory '$curpath' ($!), stopped";

@mod_files = grep /\.xml(?:\.[^.]+)?$/
    => grep !/$ignore_files/
    => readdir(DIR);

closedir(DIR)
    or die "could not close directory '$curpath' ($!), stopped";

push @suffix => map { s/^(?:index|directives|quickreference)\.xml//; $_ }
       grep /^(?:index|directives|quickreference)\.xml/
    => @{[ @mod_files ]}; # copy, because $_ will be modified inline

# keep only real module files in @mod_files
@mod_files = grep !/^(?:index|directives|quickreference)\.xml/
    => grep !/-dict\.xml/
    => grep !/^allmodules\.xml/
    => @mod_files;

# now iterate over each unique extension (aka language) and check
# (possible recreate) the particular allmodules.xml file
for $ext (keys %{{map {($_ => undef)} @suffix}}) {
    # the file we finally want to write to
    my $target = docpath("mod/allmodules.xml$ext");

    my @modules;
    if (length($ext)) {
        my %is_translated = map { s/^(.*\.xml).*/$1/; ($_ => 1) }
               grep /\.xml\Q$ext\E$/
            => @{[ @mod_files ]};

        ## write list for dependency evaluation in build.xml
        my $trfile = docpath("mod/.translated$ext");
        sysopen(FILE, $trfile, O_WRONLY | O_CREAT | O_TRUNC)
            or die "could not open '$trfile' for writing ($!), stopped";

        my $content = <<"        TRFILE";
translated=@{[
       join " \\\n\t"
    => sort keys %is_translated
]}
        TRFILE

        print FILE $content
            or die "could not write into '$trfile' ($!), stopped";

        close(FILE)
            or die "could not close '$trfile' after writing ($!), stopped";

        @modules = map { $is_translated{$_} ? "$_$ext" : $_ }
            keys %{{
                map { s/^(.*\.xml).*/$1/; ($_ => undef) } @{[ @mod_files ]}
            }}
    }
    else {
        @modules = grep /\.xml$/ => @mod_files;
    }

    # bring in stable order for better comparison
    @modules = sort stable_order @modules;

    my $content = <<"    XML";
<?xml version="1.0" encoding="UTF-8"?>
<!-- GENERATED FROM XML: DO NOT EDIT -->

<modulefilelist>
  @{[ join "\n  " => map qq{<modulefile>$_</modulefile>} => @modules ]}
</modulefilelist>
    XML

    # now load the current file and get in touch with stored reality
    my $existing = '';
    if (-f $target) {
        local $/; # slurp mode

        sysopen(FILE, $target, O_RDONLY)
            or die "could not open file '$target' ($!), stopped";

        $existing = <FILE>;

        close(FILE)
            or die "could not close file '$target' ($!), stopped";
    }

    # If the stored list doesn't match the computed one,
    # replace the stored list with the computed one.
    unless ($content eq $existing) {
        sysopen(FILE, $target, O_WRONLY | O_CREAT | O_TRUNC)
            or die "could not open file '$target' ($!), stopped";
        
        print FILE $content
            or die "could not write into file '$target' ($!), stopped";

        close(FILE)
            or die "could not close file '$target' ($!), stopped";

        # report success
        print "'allmodules.xml$ext' written.\n";
    }
}

# This sort callback defines a very strict but somewhat
# "natural" sorting order
sub stable_order {
   return -1        if ($a =~ /^core/);
   return  1        if ($b =~ /^core/);
   return $a cmp $b if ($a =~ /^mod_/ and $b =~ /^mod_/);
   return -1        if ($a =~ /^mod_/ and $b !~ /^mod_/);
   return  1        if ($a !~ /^mod_/ and $b =~ /^mod_/);
   (my $x = $a) =~ s/^mpmt?_//;
   (my $y = $b) =~ s/^mpmt?_//;
   return $x cmp $y;
}

__END__
sample file:

<?xml version="1.0" encoding="UTF-8"?>
<!-- GENERATED FROM XML: DO NOT EDIT -->

<modulefilelist>
    <modulefile>core.xml</modulefile>
    <modulefile>mod_actions.xml</modulefile>
    <modulefile>mod_alias.xml</modulefile>
    <!-- ... -->
</modulefilelist>
