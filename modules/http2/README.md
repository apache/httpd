
#mod_h2 - http/2 for Apache httpd

Copyright (C) 2015 greenbytes GmbH

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.


This repository contains a Apache httpd module implementing the HTTP2
protocol. It uses nghttp2 (https://nghttp2.org) as base engine and connects
it with the Apache infrastructure.


##Status
In development. Use at your own risk. See [Known Problems](#known-problems) below for a list
of things you might encounter.

##Tested Platforms
* OS: Ubuntu 14.04, OS X 10.10
* Apache httpd 2.4.12 (patch needed)
* Openssl 1.0.1 + 1.0.2

If someone wants to test other platforms or contribute adapations in a
github pull request, she is more than welcome.


##Features
This module supports the protocols "h2" (HTTP2 over TLS) and "h2c" (HTTP2 over plain
HTTP connections via Upgrade). You can enable it for the whole server or
for specific virtual hosts only. More on this below on "Configuration".

Specifically, the protocols "h2", "h2-16", "h2-14" and its "h2c" cousins
are announced to clients. Support for "h2-14" and "h2-16" is expected to
disappear silently as these are no standard and are currently being used
for the interop testing phase only.

##Configuration
The test setup in test/conf/* that gets installed in gen/install for the
local httpd build contains some simple examples of how this module can
be configured.

There are several configuration commands available when mod_h2 is loaded,
such as:

* H2Engine (on/off), "on"    to enable HTTP/2 protocol handling, default: off
* H2MaxSessionStreams n      maximum number of open streams per session, default: 100
* H2InitialWindowSize n      initial window size on client DATA, default: 16k
* H2MaxHeaderListSize n      maximum acceptable size of request headers, default: 64k
* H2MinWorkers n             minimum number of worker threads per child, default: mpm configured MaxWorkers/2
* H2MaxWorkers n             maximum number of worker threads per child, default: mpm configured thread limit/2
* H2StreamMaxMemSize n       maximum number of bytes buffered in memory for a stream, default: 64k
* H2AltSvc name=host:port    Announce an "alternate service" to clients (see https://http2.github.io/http2-spec/alt-svc.html for details), default: empty
* H2AltSvcMaxAge n           number of seconds Alt-Svc information is valid, default: will not be sent, specification defaults to 24h
* H2SerializeHeaders (on/off), "off"   serialize/parse request+response headers for streams, as if they arrived in HTTP/1 format. When off, certain parts of httpd core filters are disabled/replaced to allow for a more efficient handling. 
* H2HackMpmEvent (on/off), "on"        performs a hack on internal connection in order to make mpm_event working, has no effect on other mpm modules
* H2Direct (on/off), "on"    to enable h2c direct mode on a non-TLS host, default: off
* H2BufferOutput (on/off),   if output data shall be buffered. "on" for TLS connections, "off" otherwise
* H2BufferSize n             size of output buffer (if enabled), defaults to 64k
* H2BufferWriteMax n         max. number of bytes in a single write when buffering output, defaults to 16k
* H2SessionExtraFiles n      number of extra file handles a session might keep open to improve performance, depends on mpm module used and ulimit of processes, defaults to 5

All these configuration parameters can be set on servers/virtual hosts and
are not available on directory level. Note that Worker configuration is
only relevant on the base apache server and will be read - but ignored -
on any virtual hosts.


##Dependencies
1. The module is written in plain C and links to libnghttp2 and the
apache runtime. Currently, only nghttp2 version 0.7.x are supported. nghttp2 v1.0.0 introduced a incompatible API change. mod_h2 will change once there is a curl release working with 1.0.0. That release of mod_h2 will then stop support for nghttp2 0.7.x. Heads up.
1. For "h2" support - the part of HTTP2 that uses TLS - a patched mod_ssl
needs to be present in the server. The patch is available in httpd/patches
and automatically applied in sandbox mode.
1. For ALPN/NPN protocol negotiation (the basic TLS HELLO part) to work,
at least OpenSSL 1.0.1 is needed (OpenSSL 1.0.2 perferred).
1. mod_h2 is tested with the `mpm_worker` module. The `mpm_event` module is supported by a hack at the moment, handle with care.


##Installation
mod_h2 is using autoconf/automake for configuration and build handling. If you
have a git checkout, refer to 'Build from git' below. If you have a release
extracted, you need to:
```
> cd mod_h2-x.x.x
> ./configure
> make
```

For general handling of 'configure', see INSTALL. For mod_h2 specifically,
there are two arguments to know:
* `--enable-sandbox`     build a complete sandbox installation with own httpd, own libnghttp2
* `--enable-werror`      build with tons of compiler diagnostics enabled
* `--with-apxs=<pathtoapxs>` for a non-sandboxed installation where the apxs (from the apache development environment) is in an unusual location.

If you run 'configure' without arguments, it assumes a non-sandbox'ed built
where apxs and libnghttp2 are properly installed.


###Sandbox Installation:

The sandbox installation puts everything in ./gen/install: httpd, nghttp2, curl
and other fine things. For testing the module, or just trying it out, this
has the following advantages:
* conflicts with "wrong" versions already installed on your system are avoided
* you can do the installation and test without root privileges
* certain patches can be applied that are necessary for all features to work, see "Dependencies"."


##Build from git
Building from git is easy, but please be sure that at least autoconf 2.68 is
used::
```
> autoreconf -i
> automake
> autoconf
> ./configure
> make
```

##Supported Platforms
mod_h2 has been developed under Ubuntu 14.04 LTS and OS X 10.10. The module
itself depends only on an installed APXS (the Apache runtime platform) and
libnghttp2. As long as both are present, the module itself should build
just fine.

Ubuntu :Install the prerequisite software. On a 14.04 LTS server, that should be:
```
> sudo apt-get install git gcc g++ libpcre3-dev libcunit1-dev libev-dev libjansson-dev libjemalloc-dev cython make binutils autoconf automake autotools-dev libtool pkg-config zlib1g-dev libssl-dev libxml2-dev libevent-dev python3.4-dev libevent-openssl-2.0-5 php5-cgi
```

OS X: on OS X 10.10, building the project requires a homebrew installation and the following packages installed via brew:
* pkg-config
* for httpd the Makefile will download and install:
    * pcre
    * apr + apr-util
    * openssl
  exact versions and download urls in httpd/Makefile
* for nghttp2 the Makefile will download and install:
    * zlib
    * libev
  exact versions and download urls in httpd/Makefile
* for sandbox tests you will need php5-cgi from homebrew

##Architecture, Limits, Details
See DISCUSS.


##Sandbox Testing
The sandbox build contains some test cases. In order to run those, you
need to:
```
> make
> make install
> make test
```
The sandbox creates its own httpd and nghttp2 installation in gen/install
and configures httpd to run on ports 12345+12346 (TLS). It also generates
a self-signed certificate for the servers under the name test.example.org
and test-ser.example.org.
You should make entries in /etc/hosts like
```
127.0.0.1       test.example.org        test
127.0.0.1       test-ser.example.org    test
```
for tests to work properly.

Another issue is testing with browsers like Chrome or Firefox. If you point
them at test.example.org, they will complain about the self-signed certificate,
offer you to connect anyway and, if you choose that, refuse to work. I think
they have a much stricter cert checking for HTTP/2 and the UI needs an update
here.

I myself configure an additional site into the sandbox server with a real
certificate and test browsers successfully there. But I cannot share this
certificate with the world. If there is a better way to test browser interop,
I am happy to be given pointers.

#Known Issues
* If you use the "prefork" mpm, there are reported problems with using mod_h2 and mod_prody/mod_rewrite against another server which disappear when using mpm_event or mpm_worker in the otherwise unchanged configuration.
* If you test chrome/firefox against a httpd with mod_h2 and get "ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY", this means that the browser considers the installed SSL certificates as not good enough to use HTTP/2. This will happen with the sandbox installation, as that one has only a self-signed certificate. If you disable mod_h2, chrome/firefox will seem to be working fine again against your server. This is due to the fact that SSL requirements are, for backward compatibility, relaxed when talking HTTP/1. Unfortunately, chrome/firefox do currently not offer a better user experience in indicating what part of the certificate was considered inadequate. For example, certain signing algorithms in combination with expiration dates are no longer accepted. This becomes pretty hard to debug for someone not fluent in TLS and PKI.
* Some modules will not be fully compatible with HTTP/2 connections. mod_logio, for example, will not properly report the accumulated traffic per connection as requests are handled in sub-connecition and that data is never aggregated.

##TODO
* Thanks to the excellent nghttp2, the module currently supports stream priority
handling, but nghttp2 offers at the moment (v0.7.15) no way to use the prio
information for request scheduling.
* mpm_event: supported by a hack atm. Needs an official patch with an Optional
function
* http trailers are not implemented
* mod_h2 removes reqtimeout input filter for its connection. 
  

##Licensing
Please see the file called LICENSE.


##Credits
This work has been funded by the GSM Association (http://gsma.com). The module
itself was heavily influenced by mod_spdy, the Google implementation of their
SPDY protocol. And without Tatsuhiro Tsujikawa excellent nghttp2 work, this
would not have been possible.


Münster, 20.05.2015,

Stefan Eissing, greenbytes GmbH
