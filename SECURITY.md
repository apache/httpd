
# Apache httpd Security Policy

This document is an overview of the security model for Apache
httpd. Security vulnerabilities reported to the project need to
demonstrate how an attacker can violate the security model.

## Supported Versions

Currently the only supported version is the latest patch release of the
`2.4.x` stable branch. Vulnerabilities which exist *only* in
unreleased branches (such as `trunk`) may be treated as normal bug
reports.

## Reporting Vulnerabilities

For information on how to report a new security problem please see
[here](http://httpd.apache.org/security_report.html). The process of
reporting and handling vulnerabilities is out of scope for this
document.

For a list of already-addressed vulnerabilities, see [Apache 2.4 Security
Vulnerabilities](http://httpd.apache.org/security/vulnerabilities_24.html)

## Model scope

If an issue is reported against an aspect of the security model which
is not documented here, it MUST be accompanied by a clear description
of that aspect the model, showing why a trust boundary exists and how
it is violated. It is helpful to use references to vulnerabilities
previously disclosed by this project, the httpd documentation
(see docs/manual), and to demonstrate common usage patterns.

Any security vulnerability SHOULD be reproducible:

1. under a reasonable, supported configuration.
2. without using third-party modules, or modules explicitly designed
  for debugging.
3. under a standard build on a supported platform.

Issues which are reproducible only using instrumented builds (such as
ASAN, or under valgrind) should be clearly explained as such.

## Basic model

Processing of requests by remote untrusted users (HTTP clients) MUST
NOT crash or prematurely terminate server processes, nor gain code
execution privileges.  In the default configuration, timeouts are
applied to most aspects of HTTP request handling such that a single
idle client connection SHOULD NOT tie up a single processing thread or process
indefinitely.

It is the responsibility of the server administrator to tune and
configure httpd appropriately to the operating environment, for
example adjusting MPM limits (see
https://httpd.apache.org/docs/trunk/misc/security_tips.html).

Denial of service attacks are expected to be mitigated at firewall or
network level. It is expected that an attacker who is able to
establish multiple simultaneous connections to the server will, to
some extent, deny service to other remote users. 

Example vulnerabilities which violated the model: CVE-2026-23918,
CVE-2004-0786.

## Resource Consumption

Handling requests entails resource consumption (CPU, memory, disk
space for logs, etc). It is expected that resource consumption by the
server is at worst proportional to the volume of network traffic.

Memory consumption by a single request should be capped, with
configurable limits; e.g. LimitRequestFields limits the RAM
consumption by HTTP headers, LimitXMLRequestBody limits the RAM
consumption by parsing XML request documents.

Example vulnerabilities which violated the model: CVE-2004-0942

## Privilege separation on Unix platforms

On Unix platforms, when httpd is started as the root user, privilege
separation is used between the parent process which retains root
privileges, and child processes (and threads). Child processes/threads
run as a less-privileged user and group which is configurable via the
`mod_unixd` module, https://httpd.apache.org/docs/2.4/mod/mod_unixd.html

The less-privileged user:

* MUST be restricted from gaining root privileges, and
* SHOULD NOT have read or truncate access to log files

but otherwise has full control over network communication with
clients, and, for example, retains access to SSL private key data in a
typical configuration.

Use of platform-specific sandboxing or security features (such as use
of containers, chroot, SELinux) are out of scope for this security
model.

Example vulnerabilities which violated the model: CVE-2007-3304,
CVE-2012-0031.

## Delegated Configuration 

Server configuration can be delegated to trusted local site authors by
allowing use of .htaccess files in non-default configurations.  Local
site authors are trusted to not attack the server with malformed or
malicious .htaccess files (for example, files of excessive size).

In configurations supporting in-process scripting language interpreters
which are not sandboxed, such as `mod_lua` or `mod_php`, local site
authors have equivalent privileges to the less-privileged server user.

(### TODO something about AllowOverride)

## Dependent Services

Many configurations depend on backend servers or services which are
trusted entities.

Services used for authentication or caching privileged/protected data
are trusted not to attack the web server. Examples of trusted services
include, but are not limited to:

* Database or LDAP servers used for authentication via `mod_ldap` or `mod_dbd`
* Redis/Valkey, or Memcache servers used for the `mod_ssl` session cache
* OCSP servers used for client certificate verification, or server certificate "stapling"
* ACME servers used for issuing certificate in `mod_md`.

Backend servers are those accessed in a reverse proxy (or gateway)
configuration, typically via HTTP or AJP (see
https://httpd.apache.org/docs/current/mod/mod_proxy.html#forwardreverse).
Backend servers are trusted to provide content but SHOULD NOT be able
to influence HTTP protocol framing logic in the frontend (client)
communication (so called "response splitting" attacks).

Example vulnerabilities which violated the model: CVE-2026-33523,
CVE-2024-42516.
