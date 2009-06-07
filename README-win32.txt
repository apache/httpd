New version of APR
------------------

Note that the included APR is now version 1.3, which adds several
subtle changes in the behavior of file handling, pipes and process
creation.  Most importantly, there is finer control over the handles
inherited by processes, so the mod_fastcgi or mod_fcgid modules must 
be updated for httpd-2.2.9 to run correctly on Windows.

Most other third party modules are unaffected by this change.


Source corrections applied
--------------------------

The -win32-src.zip package includes corrections to the Makefile.win
build file so that .mak based builds work.  The package also corrects
the default to disable IPV6 support.  These patches are summarized in
the httpd-2.2.9-win32-src.applied.patch file.


Connecting to databases
-----------------------

With APR-util 1.3.0, the MySQL and FreeTDS drivers do not compile
on Windows.  There is no Microsoft SQL Server client or ODBC client
at the present time.

Three driver connectors are provided in the binary distribution, for
SQLite3, PostgreSQL and Oracle.  They require you to install the actual 
corresponding client drivers.

The sqlitedll.zip binary file can be obtained from;

http://www.sqlite.org/download.html

note that this binary was built with version 3.5.9 (earlier and
later version 3.5 driver .dll's may work.)

The Oracle Instant Client - Basic driver can be obtained from

http://www.oracle.com/technology/software/tech/oci/instantclient/htdocs/winsoft.html

and note that this binary was built against version 11.1.0.6.0,
other version 11.1 drivers may work.

The PostgreSQL binaries may be obtained from

http://www.postgresql.org/ftp/binary/v8.3.1/win32/

and note that this binary was built against version 8.3.1-1, and
again it may work with other 8.1 version .dll's.

For whichever database backend you configure, the corresponding driver
.dll's must be in your PATH (and in the systemwide path if used for 
a service such as Apache httpd).

