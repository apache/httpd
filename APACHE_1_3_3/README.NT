                            Apache for Windows
                           Version 1.3 (and up)

What is it?
-----------

Apache is an HTTP server, originally designed for Unix systems. This
is the first major release of Apache for Windows systems, including
Microsoft Windows NT, 98, and 95.  Like the Unix version, it includes
many frequently requested new features, and has an API that allows it
to be extended to meet users' needs more easily. It also allows ISAPI
extensions.

Documentation
-------------

The documentation available as of the date of this release is also
included, in HTML format, in the <./htdocs/manual/> directory.
For the most up-to-date documentation, visit us on the WWW at
<http://www.apache.org/>. For Windows specific information, see
<http://www.apache.org/docs/windows.html>.

WARNING
-------

Apache on Win32 has not yet been optimized for performance.  Apache still
performs best, and is most reliable on Unix platforms.  Over time we
will improve performance for Windows NT. Folks doing comparative reviews
of webserver performance are asked to compare against Apache on a Unix
platform such as Solaris, FreeBSD, or Linux.

Apache on Win32 should still be considered beta quality code.  It does not
meet the normal standards of stability and security that Unix releases do.

Installation or Compilation Instructions
----------------------------------------

See the website <http://www.apache.org/docs/windows.html> for details of
how to install Apache from a binary release or how to compile Apache
from scratch. This file is also included in the distribution as
<./htdocs/manual/windows.html>.

Known Problems
--------------

To get information about the current set of known problems, see our
online bug reporting database at <http://www.apache.org/bug_report.html>.
In particular, search for problem reports under the category "os-windows".

This is a rough list of what we know has not been implemented on Win32.

- The User directive is not supported. If you run apache as a service,
  you can change the user it runs as by going to 
  Control Panel->Services->Startup

- suexec doesn't work

- RFC 1413 (IdentityCheck) is not yet ported

- If you have a very busy server, when a server child process exits,
  any connections made to that child process that have not yet been
  accepted by it are aborted.

- The regex library build does not generate *.ih headers.

- Multithreading is not properly abstracted

- htpasswd passwords are stored in plain text because Windows lacks a
  crypt() function

Licensing
---------

Please see the file called LICENSE.

Acknowledgments
----------------

We wish to acknowledge the following copyrighted works that make up
portions of the Apache software:

Portions of this software were developed at the National Center for
Supercomputing Applications at the University of Illinois at
Urbana-Champaign.

This software contains code derived from the RSA Data Security Inc. MD5
Message-Digest Algorithm, including various modifications by Spyglass Inc.,
Carnegie Mellon University, and Bell Communications Research, Inc.
(Bellcore).

This package contains software written and copyrighted by Henry Spencer.
Please see the file called src/regex/COPYRIGHT.

The NT port was started with code provided to the Apache Group
by Ambarish Malpani of ValiCert, Inc. (www.valicert.com).
