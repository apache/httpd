NOTE - About this File
 ======================

This file contains development information on Apache for Windows, not all
of which is relevant to the current version. For information on
installation and use of Apache for Windows, please see
http://www.apache.org/docs/windows.html, also available as
htdocs/manual/windows.html with this distribution.

Alexei Kosut <akosut@apache.org> - July 21, 1997

Integration with official Apache sources
 ========================================

Ben Laurie <ben@algroup.co.uk>

Starting with a port to NT by Ambarish Malpani (see below).

Things done
-----------

1. Move NT-specific stuff to the NT subdirectory

2. Eliminate code under incompatible licenses.

3. Rearrange changes to minimise the patch.

4. Add pregenerated modules.c to NT dir, for now.

5. Include nt/ files directly, rather than building a library.

6. Remove gratuitous layout changes.

7. Fold in missing updates.

8. Add in mod_info.c (not tested).

9. Made a start on mod_rewrite.c, brought back into line with current source.

10. Remove copy of environment in util_script.c, presumably introduced through
    a misunderstanding.

11. Replace crypt with a null function.

Things to do
------------

1. Make regex generate *.ih headers.

2. Use Configuration to generate modules.c.

3. Consider including regex/ directly, rather than building a library.

4. Make multithread routines null #defines rather than null functions when
   not multithreading.

5. Change __declspec(thread) to APACHE_TLS throughout.

6. Tidy up http_main.c.

7. Update OS/2 comments to mention Win32 where appropriate

8. Abstract log children!

9. Wonder why "bytes" in mod_negotiation is a float?

10. Fix the 3 zillion warnings we get under VC++.

11. Replace crypt().

Apache on Windows NT
 ====================

Ambarish Malpani
ambarish@valicert.com


This document consists of my goobly-gook, over and above all the wonderful
Apache related writeups available in other places (including this directory).

Finally, a Web server that can run on Windows NT Workstation and Windows 95
and a FREE proxy server!!!

This is a port of Apache to Windows NT. I have basically used the sources
from Apache 1.2b10.

I have put out the sources on:

ftp://valicert.com/pub/apache_1_2b10_nt.tar.gz. These same sources will
compile on Unix, but you will need to remove the \r from the \r\n at
the end of ever text file.

Stuff specific to the NT version:
--------------------------------

1. It is multithreaded
2. It can run as a service (execute apache -i to install the service)
    or as a regular program (execute apache -s to avoid waiting for
    the program to hook up to the Service Manager).
3. It executes as multiple servers (this allows for some fault tolerance -
    if a server dies, another one takes its place. Also after dealing
    with a certain number of requests, a server voluntarily exits, to
    clean up any resources it might have forgotten to free up).
4. cgi scripts work.

As a default, the daemon looks for the httpd.conf file at
/usr/local/etc/httpd/conf ON THE DRIVE WHERE THE EXECUTABLE exists.

There are a couple of new options:
ThreadsPerChild (number of threads each server spawns)
ExcessRequestsPerChild (number of additional requests a server responds
                to, after it decides to exit)

Due to the behavior of NT when multiple processes have a socket open
for listening, I would recommend that you set the following in httpd.conf
(in the directory /usr/local/etc/httpd/conf):

# Start up 3 servers (in case one dies, another can take its place, while
# a new one is spawned
StartServers 3

# Don't force a server to exit after it has served some number of requests.
# If you do want server's to exit after they have run for a long time (to
# help the system clean up after the process), please set this to a pretty
# large number - like 10,000. What this will do, is, each child server will
# exit after serving 10,000 requests, and another server will take its place.
MaxRequestsPerChild 0

# Number of concurrent threads at a time (set the value to more or less
# depending on the responsiveness you want and the resources you wish
# this server to consume).

ThreadsPerChild 20

TO BUILD THE EXECUTABLE
-----------------------

You will need access to Microsoft's Visual C++ compiler. I have used
version 4.2. You might be able to get away with earlier/later versions.

Run the command nmake -f Makefile.nt in the src directory.


TO INSTALL/RUN THE APACHE SERVER
--------------------------------

You can run the Apache either as a regular executable, or as a service.
To run Apache as a regular executable:
apache -s            (the -s tells it not to connect to the service manager)

To run Apache as a service (recommended), you need to first install the
apache and then start the service.
apache -i            (installs the service)
Go to the Control Panel, start up the Services item, select the Apache service
            click on the Start button.
Note: Apache will be started automatically when you reboot your machine. If
you want to change this behavior, you can change the startup options by
clicking on Control Panel->Services->Startup...


Tasks Not Yet Done
------------------
- The User directive is not supported. If you run apache as a service,
you can change the user it runs as by going to Control Panel->Services->Startup
- suexec doesn't work
- RFC 1413 not yet ported

Known Problems
--------------
- If you have a very busy server, when a server child process exits,
any connections made to that child process that have not yet been
accepted by it are aborted.
- Problem with very long running cgi scripts (their output is garbled?)
- There are problems with the way the program handles cgi scripts that
it doesn't successfully spawn.
- On Windows 95, there seems to be a problem spawning cgi scripts, since
Windows 95 seems to require \'s in the path (unlike NT, which accepts /'s).

Hope this helps,
Feedback is very, very welcome!!!

Ambarish


Legal stuff: All copyrights are properties of their respective owners. This
source code is being returned to the Apache group and will hopefully become
part of their regular distribution over time.
