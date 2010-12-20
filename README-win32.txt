New version of APR
------------------

Note that the included APR is now version 1.3, which adds several
subtle changes in the behavior of file handling, pipes and process
creation.  Most importantly, there is finer control over the handles
inherited by processes, so the mod_fastcgi or mod_fcgid modules must 
be updated for httpd-2.2.9 to run correctly on Windows.

Most other third party modules are unaffected by this change.


Connecting to databases
-----------------------

Five SQL driver connectors (dbd) are provided in the binary distribution, 
for MySQL, SQLite3, PostgreSQL, Oracle and ODBC.  Two keyed database
connectors are provided, SDBM and Oracle Berkeley DB.  All but SDBM will
require you to install the corresponding client driver libraries.

The sqlitedll.zip binary (containing sqlite3.dll) can be obtained from
  http://www.sqlite.org/download.html
note that this binary was built with version 3.6.16 (earlier and later
version 3.6 driver .dll's may work.)  The lib binding is created using
LIB /DEF:sqlite3.def and using the .h files from the _amalgamation zip.

The Oracle Instant Client - Basic driver can be obtained from
  http://www.oracle.com/technology/software/tech/oci/instantclient/htdocs/winsoft.html
and note that this binary was built against version 11.1.0.6.0,
other version 11.1 drivers may work.

The PostgreSQL client binaries may be obtained from
  http://www.postgresql.org/ftp/binary/v8.3.1/win32/
and note that this binary was built against version 8.3.1-1, and
again it may work with other 8.1 version .dll's.

The MySQL client binaries ("Essentials" is sufficient) is obtained from 
  http://dev.mysql.com/downloads/mysql/5.1.html#win32
but note that once using the MySQL database, the applicable exception 
clause demands copy-left terms on the resulting combination.

The Oracle Berkeley DB binaries may be obtained from 
  http://www.oracle.com/technology/software/products/berkeley-db/index.html
but note that once using the Berkeley DB code, the Oracle license
demands copy-left terms on the resulting combination.

NOTE: For whichever database backend(s) you configure, the corresponding
driver .dll's must be in your PATH to test from console mode, and in the 
systemwide path if used for a service such as Apache httpd.

The FreeTDS driver is not built on Windows, since the Microsoft ODBC is 
provided instead.  The sqlite2 and ndbm drivers are not used on Windows, 
as there is no point in legacy support of these old versions.  The ASF
does not distribute binary builds of the gdbm binding.

