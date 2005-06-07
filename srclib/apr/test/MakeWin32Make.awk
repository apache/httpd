{

    if (match($0, /\@INCLUDE_RULES\@/ ) ) {
        print "ALL: \$(TARGETS)";
	print "";
        print "CL = cl.exe";
        print "LINK = link.exe /nologo /debug /machine:I386 /subsystem:console /incremental:no ";
	print "";
        print "CFLAGS = /nologo /c /MDd /W3 /Gm /GX /Zi /Od /D _DEBUG /D WIN32 /D APR_DECLARE_STATIC /FD ";
	print "";
        print ".c.obj::";
        $0 = "\t\$(CL) -c \$< \$(CFLAGS) \$(INCLUDES)";
    }
    if ( match( $0, /^ALL_LIBS=/ ) ) {
        $0 = "";
    }
    if ( match( $0, /^LOCAL_LIBS=/ ) ) {
        print "LOCAL_LIBS= ../LibD/apr.lib ";
        print "ALL_LIBS= kernel32\.lib user32\.lib advapi32\.lib Rpcrt4\.lib ws2_32\.lib wsock32\.lib ole32\.lib ";
	$0 = ""
    }
    if ( match( $0, /\@CFLAGS\@/ ) ) {
        $0 = "";
    }
    gsub( /\$\([^\)]* [^\)]*\)/, "", $0 );
    gsub( /\$\{LD_FLAGS\}/, "", $0 );
    gsub( /\.\.\/libapr\.la/, "../LibD/apr.lib", $0 );
    gsub( /\@RM\@/, "del", $0 );
    if (gsub( /\$\(RM\) -f/, "del" ) ) {
	gsub( /\*\.a/, "*.lib *.exp *.idb *.ilk *.pdb", $0 );
	gsub( /Makefile/, "Makefile *.ncb *.opt", $0 );
    }
    gsub( /\@CC\@/, "cl", $0);
    gsub( /\@RANLIB\@/, "", $0);
    gsub( /-I\$\(INCDIR\)/, "/I \"$(INCDIR)\"", $0);

    gsub( /\.\.\/libapr\.a/, "../LibD/apr.lib", $0 );
    if ( gsub( /\@EXEEXT\@/, ".exe", $0 ) ) {
        gsub( /\$\(CC\) \$\(CFLAGS\)/, "\$\(LINK\) /subsystem:console", $0 );
        gsub( /-o (\S+)/, "/out:\"$1\"", $0 );
        gsub( /--export-dynamic /, "", $0 );
        gsub( /-fPIC /, "", $0 );
    }
    if ( gsub( /-shared/, "/subsystem:windows /dll", $0 ) ) {
        gsub( /-o (\S+)/ "/out:\"$1\"", $0 );
    }
    gsub( /\$\(NONPORTABLE\)/, "", $0 );
    gsub( /\.a /, ".lib ", $0 );
    gsub( /\.o /, ".obj ", $0 );
    gsub( /\.lo /, ".obj ", $0 );

    print $0;
}
