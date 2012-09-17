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
# It gets two parameters, ${input_ext} (e.g. .xml.de) and the full path name
# of the current directory.
# It assumes, that the current working directory is the root of the manual.

# The script doesn't use an XML parser (yet?) so care should be taken with
# non-ascii characters.

# TODO:
# - rewrite in java as ant task?

# against fat fingers
use strict;
use warnings;

# for file operations
use FindBin;
use lib $FindBin::Bin;
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_TRUNC O_APPEND);
use DocUtil qw(%suffix2lang $ignore_files srcinfo docpath prefix);
sub outofdate($$$); # need Prototype

# scratch stuff
my (@files, @all_files, @pfiles, %revs, $curpath, $file);

# check commandline parameters
die "missing parameter(s)\n"
    unless defined $ARGV[0] and defined $ARGV[1];
    #              suffix               srcfile

# slurp in directory
$curpath = $ARGV[1];
opendir(DIR, $curpath)
    or die "could not open directory '$curpath' ($!), stopped";

@all_files = sort grep {
    $_ ne "allmodules$ARGV[0]" and
    $_ ne "categories$ARGV[0]"
} grep !/$ignore_files/ => readdir(DIR);

closedir(DIR)
    or die "could not close directory '$curpath' ($!), stopped";

# glob the files
@files = grep {-f $_} prefix grep /\Q$ARGV[0]\E$/ => @all_files;

for $file (@files) {
    my (%current, %variants);
    my ($dirname, $basename, $relative, $metafile) = srcinfo($file);

    # first determine the reality
    @pfiles = grep /^\Q$basename.\E(?:html\.[^.]+|xml)/ => @all_files;

    # now loop over the filelist.
    # it contains all files of one language including
    # html AND xml variants.
    for (@pfiles) {
        my $suffix;
        my $lang = $suffix = /^\Q$basename.\E(?:html|xml)\.([^.]+)/ ? $1 : 'en';
        $lang = $suffix2lang{$suffix} if $suffix2lang{$suffix};

        $variants{$lang} = {};
        $variants{$lang}->{'pdf'} = "$basename.$suffix.pdf"
            if -f docpath("$dirname$basename.$suffix.pdf");

        # the following works, because the list (@pfiles) is sorted, that way
        # html is processed before xml and thus typically we set the
        # parameter first and delete it later.
        if (/^\Q$basename.xml/) {
            delete $variants{$lang}->{'htmlonly'};
        }
        else {
            $variants{$lang}->{'htmlonly'} = 'yes';
        }

        $variants{$lang}->{outdated} = 'yes'
            if $lang ne 'en' and outofdate($dirname, $basename, $lang);
    }

    # create resulting file contents
    my $content = <<"    XML";
<?xml version="1.0" encoding="UTF-8" ?>
<!-- GENERATED FROM XML: DO NOT EDIT -->

<metafile reference="${basename}.xml">
  <basename>$basename</basename>
  <path>$dirname</path>
  <relpath>$relative</relpath>

  <variants>
    @{[
        join "\n    "
        => map
            qq{<variant@{[do{ my $lang = $_;
                map qq( $_="$variants{$lang}->{$_}")
                => keys %{$variants{$lang}};
            }]}>$_</variant>}
        => sort keys %variants
    ]}
  </variants>
</metafile>
    XML

    # read current variant file if exists
    my $existing = '';
    $curpath = docpath($metafile);
    if (-f $curpath) {
        local $/; # slurp mode /

        sysopen(FILE, $curpath, O_RDONLY)
            or die "could not open file '$curpath' ($!), stopped";

        $existing = <FILE>;

        close(FILE)
            or die "could not close file '$curpath' ($!), stopped";
    }

    # compare and possibly write new result to disk
    unless ($content eq $existing) {
        my $ppath = $metafile;
        $ppath =~ s,^/,,;

        sysopen(FILE, $curpath, O_WRONLY | O_CREAT | O_TRUNC)
            or die "could not open file '$curpath' ($!), stopped";

        print FILE $content
            or die "could not write into file '$curpath' ($!), stopped";

        close(FILE)
            or die "could not close file '$curpath' ($!), stopped";

        # report success
        print "'$ppath' written.\n";
    }
} # for (@files)

my $no_git;
# get revision of the english original
sub reven($$) {
    my $dirname = shift;
    my $basename = shift;
    my $rev = $revs{"$dirname$basename"};

    unless ($rev) {
        my $curpath = docpath("$dirname$basename.xml");

        sysopen(FILE, $curpath, O_RDONLY)
            or die "could not open file '$curpath' ($!), stopped";

        {
            local $_;
            while (<FILE>) {
                $rev = $1, last if /<!-- \044LastChangedRevision:\s*(\S+)\s*\$ -->/;
            }
        }

        close(FILE)
            or die "could not close file '$curpath' ($!), stopped";

        $revs{"$dirname$basename"} = $rev;
    }
    unless ($rev || $no_git) {
        # LastChangedRevision is not available with git-svn or a git checkout
        # from git.apache.org. Try to get the revision from the log.
        my $curpath = docpath("$dirname$basename.xml");
        # XXX: This does not work if there has been a local commit
        my $log = qx{git log -1 $curpath 2> /dev/null};
        if ($? == 0) {
            if ( $log =~ /git-svn-id:[^\@]+\@(\d+)\s/ ) {
                $revs{"$dirname$basename"} = $rev = $1;
            }
        }
        else {
            # no git repo
            $no_git = 1;
        }
    }

    return $rev;
}

# check out-of-dateness of a file
sub outofdate($$$) {
    my $dirname = shift;
    my $basename = shift;
    my $lang = shift;

    if (/^\Q$basename.xml/) {
        my $ood = 0;
        my $reven = reven($dirname, $basename);

        if ($reven) {
            my $curpath = docpath("$dirname$_");
            my ($rev, $orev);

            # grab the revision info from the source file
            sysopen(FILE, $curpath, O_RDONLY)
                or die "could not open file '$curpath' ($!), stopped";
            {
                local $_;
                while (<FILE>) {
                    $rev = $1, $orev=$2, last
                        if /<!--\s*English\s+Revision\s*:\s*([^\s:]+)
                            (?::(\S+)\s+\(outdated\))?\s+-->/xi
                                             or
                           /<!--\s*English\s+Revision\s*:\s*(\S+)\s+
                            (?:\(outdated:\s*(\S+)\s*\)\s+)?-->/xi;
                }
            }
            close(FILE)
                or die "could not close file '$curpath' ($!), stopped";

            # if outdated, take some action
            if ($rev and $rev ne $reven) {
                # note the actual revision in the source file
                unless ($orev and $orev eq $reven) {
                    my $cont;
                    sysopen(FILE, $curpath, O_RDONLY)
                        or die "could not open file '$curpath' ($!), stopped";
                    {
                        local $/; # slurp mode
                        $cont = <FILE>;
                    }
                    close(FILE)
                        or die "could not close file '$curpath' ($!), stopped";

                    unless (
                        $cont =~ s{<!--\s*English\s+Revision\s*:\s*([^\s:]+)
                                   (?::\S+\s+\(outdated\))?\s+-->}
                            {<!-- English Revision: $1:$reven (outdated) -->}ix
                    ) {
                        $cont =~ s{<!--\s*English\s+Revision\s*:\s*(\S+)\s+
                                   (?:\(outdated[^)]*\)\s+)?-->}
                            {<!-- English Revision: $1:$reven (outdated) -->}ix
                    }

                    sysopen(FILE, "$curpath.tmp", O_WRONLY | O_CREAT | O_TRUNC)
                        or die "could not open file '$curpath.tmp' ($!), stopped";
                    print FILE $cont
                        or die "could write file '$curpath.tmp' ($!), stopped";
                    close(FILE)
                        or die "could not close file '$curpath.tmp' ($!), stopped";

                    rename "$curpath.tmp", $curpath
                        or die "could not rename $curpath.tmp -> $curpath ".
                               "($!), stopped";

                    print substr($dirname, 1), $_, " adjusted (refers to: ",
                          $rev, ", current is: $reven)\n";
                }

                # record the filename for later output on the terminal
                $curpath = docpath(".outdated.$lang");
                sysopen(FILE, $curpath, O_WRONLY | O_CREAT | O_APPEND)
                    or die "could not open file '$curpath' ($!), stopped";

                print FILE substr("$dirname$_\n", 1);

                close(FILE)
                    or die "could not close file '$curpath' ($!), stopped";

                return 23; # true, soo true.
            }
        }
    }

    return;
}

__END__
sample file:

<?xml version="1.0" encoding="UTF-8" ?>
<!-- GENERATED FROM XML: DO NOT EDIT -->

<metafile reference="quickreference.xml">
  <basename>quickreference</basename>
  <path>/mod/</path>
  <relpath>..</relpath>

  <variants>
    <variant pdf="quickreference.en.pdf">en</variant>
    <variant outdated="yes">ja</variant>
  </variants>
</metafile>
