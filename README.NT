                              Apache for Windows
                             Version 1.3 (and up)

What is it?
-----------

Apache is an HTTP server, originally designed for Unix systems. This
is the first release of Apache for Windows systems.  Like the Unix
version, it includes many frequently requested new features, and has
an API which allows it to be extended to meet users' needs more
easily. It also allows ISAPI extensions.

Documentation
-------------

The documentation available as of the date of this release is also
included, in HTML format, in the htdocs/manual/ directory. For the
most up-to-date documentation, visit us on the WWW, at
http://www.apache.org/. For Windows specific information, see
http://www.apache.org/docs/windows.html.

WARNING
-------

Apache on NT has not yet been optimized for performance.  Apache still
performs best, and is most reliable on Unix platforms.  Over time we
will improve NT performance. Folks doing comparative reviews of
webserver performance are asked to compare against Apache on a Unix
platform such as Solaris, FreeBSD, or Linux.

Changes for the Windows version
-------------------------------

1. It is multithreaded

2. It can run as a service (run apache -i to install the service)
   or as a regular program (run apache -s to avoid waiting for
   the program to hook up to the Service Manager). On Windows 95
   it runs as a regular program.

3. There is only ever one child process for handling requests.
   However for fault tolerance, if this process dies, another one
   takes its place. Also after dealing with a certain number of
   requests, each process voluntarily exits, to clean up any resources
   it might have forgotten to free up.

By default Apache uses the directory \Apache for the ServerRoot ON THE
DRIVE WHERE THE EXECUTABLE EXISTS. This can be changed with the -d
command line argument.

There are a couple of new directives:

ThreadsPerChild         - Number of threads to use to handle requests
ExcessRequestsPerChild  - Number of additional requests a server responds
                          to, after it decides to exit (this is not
                          currently used)

Compilation
-----------

If you have downloaded the source code you will need to compile
it. This requires Microsoft Visual C++ version 5.0 or higher. 

To compile Apache, run the command

   nmake -f Makefile.nt _apacher

in the src directory. To install Apache to the \Apache directory, run

   nmake -f Makefile.nt installr

You cannot easily use a different installation directory. You can also
build debug versions of Apache, with the targets "_apached" and
"installd".

Make sure that before you run "nmake" that you've run VCVARS32.BAT
so that your environment is configured to run nmake from the command
line.

To build Apache within MSVC, you will need to build the following
projects in this order. Make sure that you build the same
configuration (i.e. Debug or Release) for all of the various projects.

   regex/Makefile.dsp
   ap/ap.dsp
   os/win32/ApacheOS.dsp
   src/ApacheCore.dsp
   src/Apache.dsp

Additional modules can also be built using project files in the os/win32
directory.

Installing a Binary Release
---------------------------

The binary release is not yet available.

Running Apache
--------------

Apache can run as either a service (NT only) or a regular executable. 

To run as an executable, simply run apache.exe from the command
line. This will print the version number, then wait to serve
requests. If the server root is a directory other than \Apache, use
the -d option to give the correct server root, or store it in the
registry (see below).

To stop Apache, press Control-C to stop it running. Note
that there may be a delay between typing the command line and Apache
being ready to accept requests as it checks the service manager. Use
the -s option to prevent this delay.

When Apache starts it will look at the registry key

  HKEY_LOCAL_MACHINE\Software\Apache Group\Apache\1.3 beta\ServerRoot

to find the server root, unless specified by the -d command line
flag. The correct server root is stored in this key by the binary
installation, or when Apache is run with the -i option.

To install Apache as a service on NT and set the server root registry
key, run

  apache -i -d serverroot

This will store the value of "serverroot" into the Apache ServerRoot
registry key, as above. Note that this can be used on both Windows NT
and Windows 95, however it will not install a service on 95.

On NT you can now start the Apache service within the service manager
(Control Panel, Services), and set it to start automatically at boot
time if required. You can also stop Apache from the manager.

To remove the Apache service, run

  apache -u

Uninstalling Apache
-------------------

If you installed a binary release, you can uninstall Apache using the
normal method of removing programs (Start menu, Control Panel,
Add/Remove Programs). You may have to remove the directory manually
because of the configuration files.

If you installed a source release, you should delete the directory
where you installed Apache. You might also want to delete the registry
key, as given above.

Known Problems
--------------

- The User directive is not supported. If you run apache as a service,
  you can change the user it runs as by going to 
  Control Panel->Services->Startup

- suexec doesn't work

- RFC 1413 not yet ported

- If you have a very busy server, when a server child process exits,
  any connections made to that child process that have not yet been
  accepted by it are aborted.

- Problem with very long running cgi scripts (their output is garbled?)

- regex does not generate *.ih headers.

- Multithreadng is not properly abstracted

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
