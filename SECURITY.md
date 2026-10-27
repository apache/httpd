
# Apache httpd Security Policy

This document is an overview of the security model for Apache
httpd. Security vulnerabilities reported to the project need to
demonstrate how an attacker can violate the security model.

## Supported Versions

Currently the only supported version is the latest patch release of the
`2.4.x` stable branch.  Vulnerabilities which exist *only* in
unreleased branches (such as `trunk`) should be reported as normal bug
reports via <https://bz.apache.org/bugzilla/enter_bug.cgi?product=Apache%20httpd-2>.

## Reporting Vulnerabilities

For information on how to report a new security problem please see
[here](http://httpd.apache.org/security_report.html). The process of
reporting and handling vulnerabilities is out of scope for this
document.

For a list of already-addressed vulnerabilities, see [Apache 2.4 Security
Vulnerabilities](http://httpd.apache.org/security/vulnerabilities_24.html)

## Model scope

Every vulnerability report MUST begin with a concise, human-readable
description either:

a) clearly identifying the aspect of this security model which is
violated by the reported bug, including any applicable
[module-specific trust boundary](#module-specific-trust-boundaries), or

b) succinctly describing a trust boundary which is not covered by this
document, supported by references (such as the httpd documentation),
and showing how it is violated by the reported bug.

Reports will be rejected if they invent contrived trust boundaries, or
fail to give a simple explanation of why a trust boundary is relevant.
Verbose, AI-generated reports will often fail these tests without
sufficient human review or oversight.

Any security vulnerability SHOULD be reproducible:

1. under a reasonable, supported configuration.
2. without using third-party modules, or modules explicitly designed
  for debugging.
3. using the *latest* released sources published via <https://httpd.apache.org/download.cgi#apache24>.
4. under a standard build, on a supported platform.

Issues which are reproducible only using instrumented builds (such as
ASAN, or under valgrind) should be clearly explained as such.

Issues which depend on a specially crafted server configuration MUST
include references (such as public documentation) which show why that
is a configuration that would arise naturally in common deployments.
Special considerations also apply to any issues requiring `.htaccess`
files, per the [Delegated Configuration](#delegated-configuration) section.

It MAY be helpful to use references to vulnerabilities previously
disclosed by this project, the httpd documentation (see docs/manual),
and to demonstrate common usage patterns. Issues MUST NOT be reported
based only on the similarity to a known vulnerability; all the
requirements described here MUST be met (a reproducible bug, with a
description of the specific security impact under the model).

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

Example vulnerabilities which violated the model: CVE-2004-0942.

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
allowing use of .htaccess files in some configurations (see
https://httpd.apache.org/docs/2.4/howto/htaccess.html).  Site authors
gain a significant degree of control over, and access to, the server
at run-time:

* site authors are trusted to not attack the server with malformed or
  malicious .htaccess files

* site authors gain access to some data (such as files or the
  environment) which is otherwise restricted.

Examples of malicious `.htaccess` files include, but are not limited
to:

* configuration files of excessive size
* configurations using deliberately constructed regular expressions
  which are expensive to evaluate

In configurations where `.htaccess` files can configure in-process
code execution which is not sandboxed, such as `mod_lua` (see the
[mod_lua](#mod_lua) section below), SSI documents with `Options
Includes`, or third-party interpreters such as `mod_php`, site authors
have exactly equivalent privileges to the user which the server runs
as.

## Trusted Services

Attacks from servers and services which are implicitly or explicitly
trusted in the httpd configuration are outside the scope of the
security model.

Examples of trusted services include, but are not limited to:

* Services used for caching privileged or protected data, including
  all `mod_socache_*` providers (memcached, Redis/Valkey, distcache,
  shared memory, DBM) whether used for the `mod_ssl` session or
  stapling cache, `mod_authn_socache` credentials, or `mod_cache_socache`
* Database or LDAP servers used for authentication, authorization or
  session storage via `mod_dbd` or `mod_ldap`, including LDAP referral
  targets when `LDAPReferrals` is enabled
* OCSP servers used for client certificate verification, or server
  certificate "stapling", and CA/CRL/certificate/key files
* ACME servers used for issuing certificates in `mod_md`
* Intermediaries listed in `RemoteIPTrustedProxy`/`RemoteIPInternalProxy`,
  and PROXY protocol senders (see `mod_remoteip` below)
* The local syslog, journald and systemd services
* External programs executed by the server as configured by the
  administrator: piped loggers, `RewriteMap prg:`, `ExtFilterDefine`,
  `SSLPassPhraseDialog exec:`, `mod_md` notification commands, CGI
  programs and FastCGI/SCGI/uWSGI applications
* Loadable modules (`LoadModule`) and ISAPI extensions

Backend servers are those explicitly configured by the administrator
in a reverse proxy (or gateway) configuration, typically via
`ProxyPass`, `ProxyPassMatch`, `BalancerMember` or `RewriteRule [P]`,
using HTTP, HTTP/2, AJP, FastCGI, SCGI or uWSGI (see
https://httpd.apache.org/docs/current/mod/mod_proxy.html#forwardreverse).
Backend servers are trusted to provide content and response headers,
and bugs triggered only by a malicious backend are outside the model,
with one exception: backends SHOULD NOT be able to influence HTTP
protocol framing logic in the frontend (client) communication (so
called "response splitting" attacks).

Origin servers contacted in a *forward* proxy configuration
(`ProxyRequests On`, `CONNECT` tunnels via `mod_proxy_connect`, and FTP
servers via `mod_proxy_ftp`) are NOT trusted; they are arbitrary
network peers and are covered by the basic model.

Example vulnerabilities which violated the model: CVE-2026-33523,
CVE-2024-42516.

## Module-specific trust boundaries

The following describes trust boundaries specific to individual
modules, in addition to the general model above.

### Administrative handlers

The `balancer-manager` (`mod_proxy_balancer`), `server-status`
(`mod_status`), `server-info` (`mod_info`), `ldap-status` (`mod_ldap`)
and `md-status` (`mod_md`) handlers expose privileged information or
allow runtime reconfiguration. They MUST be protected by access
control, as described in each module's documentation. Any user granted
access to these handlers is trusted as an administrator; in particular
a `balancer-manager` user can direct traffic to arbitrary backends.
Disclosure resulting from enabling these handlers without access
control, including via `SetHandler` in `.htaccess`, is a configuration
error. The nonce and Referer checks in `balancer-manager` defend an
authorized operator against cross-site request forgery only.

### mod_sed, mod_substitute, mod_ext_filter

The sed script configured via `InputSed`/`OutputSed`, the `Substitute`
pattern and replacement, and the program configured via
`ExtFilterDefine` are trusted input. `mod_sed` scripts can read and
write any file accessible to the server user (`r` and `w` commands);
`InputSed`/`OutputSed` are not available in `.htaccess`. `Substitute`
is available to `.htaccess` authors, who are trusted per the Delegated
Configuration section.

Processing of content by `mod_sed` or `mod_substitute` may have
non-linear process or memory costs for any given script and/or regular
expression used, and computational costs for these modules is outside
the model.

### mod_proxy_hcheck

Health checks are sent to configured backends, which are trusted as
described under Trusted Services. Defects triggered only by a
malicious or malformed health-check response are outside the model.
The limits on health-check processing described in the module
documentation are robustness measures and are not a security
guarantee.

### mod_proxy_scgi

With `ProxySCGISendfile` the backend may direct the server to serve any
file readable by the server user, and with `ProxySCGIInternalRedirect`
(the default) any internal URL. This is by design: SCGI backends are
trusted at the level of the server user.

### mod_proxy_wstunnel, mod_proxy_connect, mod_proxy_fdpass

Once a protocol upgrade (101) is accepted from a configured backend,
or a `CONNECT` tunnel is established, bytes are relayed without
interpretation; the content of the tunnel is outside the model and
only timeouts apply. `CONNECT` targets are untrusted peers (see Trusted
Services). A process receiving client sockets via `mod_proxy_fdpass`
owns the connection thereafter and is fully trusted.

### mod_proxy_beacon, mod_heartbeat, mod_heartmonitor

Holders of the `ProxyBeaconSecret` are trusted as balancer
administrators. Datagrams which fail authentication or freshness
checks are untrusted network input and MUST have no effect beyond
logging. `mod_heartmonitor` accepts *unauthenticated* status packets
and `POST` requests to the `hearbeat` handler: both are only
accessible to trusted hosts.

### mod_remoteip

Client addresses asserted by proxies listed in `RemoteIPTrustedProxy`
or `RemoteIPInternalProxy` are trusted; spoofing by such a proxy is
out of scope, as is spoofing by any client when `RemoteIPHeader` is
used without a trusted proxy list (a documented misconfiguration).
Assertions from unlisted peers MUST be ignored. Listeners enabled with
`RemoteIPProxyProtocol` MUST be reachable only by the intermediaries
expected to send the PROXY protocol header; under that configuration
the PROXY header is trusted input.

### mod_cgi, mod_cgid, mod_suexec, mod_actions, mod_include

CGI programs, SSI documents with `exec` enabled, and programs invoked
via `Action`/`Script` are trusted code running as the server user (or
the `suexec` target user). Their output is trusted content but, by
default, is not trusted to control HTTP framing: `Content-Length` is
recomputed unless `ap_trust_cgilike_cl` is set and `Transfer-Encoding`
is rejected. The `mod_cgid` socket is accessible only to the server
user; processes already running as that user are within the same trust
domain. The `suexec` wrapper trusts only the server user as caller and
enforces the checks documented at
https://httpd.apache.org/docs/current/suexec.html; a target user's own
insecure scripts are out of scope.

### mod_lua

Lua scripts, and anyone able to configure them (including `.htaccess`
authors where `AllowOverride` permits the `Lua*` directives, per
[Delegated Configuration](#delegated-configuration)), are trusted with
the full privileges of the server user. mod_lua provides
no sandbox: scripts may use the `os` and `io` libraries, read and
modify server configuration via `r:config()` and the request object,
and share Lua state across requests under `LuaScope thread` or
`server`. Consequently the following are NOT vulnerabilities: any
crash, hang, resource exhaustion or disclosure caused by a script's
own actions, including calling API functions with undocumented
argument types or values, requesting unbounded allocations, or
leaking data between scripts, requests or virtual hosts through a
shared Lua state.

Scripts are responsible for bounding client-derived data they pass to
the API, for example via the `sizeLimit` argument of `r:parsebody`;
memory use proportional to a limit the script chose is by design.

Every mod_lua code path runs on behalf of a remote client, so that a
client request triggers a defect establishes nothing by itself.
Ordinary robustness bugs in mod_lua's own bindings - including, but not
limited to, memory leaks, crashes, hangs and other resource exhaustion
- are treated as ordinary bugs, not security vulnerabilities, however
they are reached; a report MUST demonstrate a security outcome beyond
the crash or leak itself, such as memory corruption a client can
leverage for code execution or a bypass of access control.

Reports MUST include the triggering Lua script and show that it is one
a careful author following the documentation would write.

### mod_rewrite

Rewrite rules and all `RewriteMap` sources (`txt`, `dbm`, `rnd`,
`prg`, `dbd`/`fastdbd`) are trusted configuration; `prg` maps run with
the privileges of the user who started the server unless configured
otherwise. Rules which pass unconstrained client input to redirect,
proxy or filesystem targets are configuration errors, as described in
the documentation. The module's default protections (such as
`AllowAnyURI` being off, and the `UnsafeAllow3F`/`UnsafePrefixStat`
flags being required) are part of the model and their bypass is in
scope.

### mod_ssl, mod_md

Certificate, key, CA, CRL and OpenSSL configuration files and
`SSLOpenSSLConfCmd` are trusted. Client certificate data is untrusted
input; identity derived from it is meaningful only when verification
succeeds against a configured CA, and `SSLVerifyClient optional_no_ca`
provides no authentication. TLS to backends authenticates the backend
only with `SSLProxyVerify require`. In `mod_md`, requests to the ACME
challenge paths, `acme-tls/1` handshakes and the public
`certificate-status` handler are untrusted client input; the ACME
server, `MDStoreDir`, and the commands configured via
`MDChallengeDns01`, `MDMessageCmd` and `MDNotifyCmd` are trusted.

### mod_session, mod_session_cookie, mod_session_crypto, mod_auth_form

A session stored in a client cookie without `mod_session_crypto` is
fully client-controlled and provides neither confidentiality nor
integrity; treating its contents as authentic is a configuration
error. With `mod_session_crypto`, forging a session without the key is
in scope. Backends and scripts able to set `SessionHeader` are trusted
to write sessions. `mod_auth_form` re-verifies session credentials on
each request; the documented risks of inline login forms and of the
`AuthFormSitePassphrase` with unencrypted sessions are out of scope.

### mod_dav, mod_dav_fs

The DAV repository, lock database and property databases are private to
the server; modification outside httpd is unsupported. Authorized DAV
users are untrusted for protocol parsing, memory safety and path
confinement, but the documented denial-of-service possibilities open
to authorized users (filling the disk, `DavDepthInfinity`,
`DavHonorMtimeHeader`) are out of scope.

### mod_cache, mod_cache_disk

Cached content from reverse-proxy backends is trusted as provided. The
on-disk cache is writable by the server user and tampering with it
requires that privilege. Cache poisoning via the origin (DNS poisoning,
request smuggling against the origin) and the documented effects of
`CacheQuickHandler On` on per-directory access control are out of
scope.

### mod_mime_magic, mod_mime_libmagic

The magic database file is trusted configuration. The file content
examined may be untrusted (for example uploaded files) and the built-in
matcher MUST handle it safely. The risks of `MimeMagicDecompression`
(off by default) are documented and out of scope; defects in libmagic
itself are third-party.

### mod_ident, DNS

The RFC 1413 "ident" service queried by `mod_ident` runs on the
client's own host and is untrusted; its response is client input and
the documentation states it is not reliable. Reverse DNS results are
controlled by the owner of the client address and are untrusted; the
server performs double-reverse lookups for `Require host`. The
configured DNS resolver, and forward DNS used when parsing the
configuration, are trusted services (see
https://httpd.apache.org/docs/current/dns-caveats.html).

### Authentication providers

Credential and group stores used by authentication and authorization
providers (`htpasswd`/DBM files, SQL via `mod_dbd`, LDAP, FastCGI
authorizers via `mod_authnz_fcgi`, cached credentials via
`mod_authn_socache`, JWT signing keys for `mod_autht_jwt`) are trusted.
Credentials and tokens presented by clients are untrusted. Configuring
`AuthtJwtVerify none` delegates trust to the transport.

### Logging

Log files, their directories and piped log programs (which run as the
user who started the server) are trusted. Client-supplied data written
to logs is escaped as documented; a client able to inject raw control
characters or forge log lines via an escaped format field violates the
model.

Example vulnerabilities which violated the model: CVE-2003-0083,
CVE-2003-0020, CVE-2013-1862, CVE-2024-47252.

### Debugging, example and experimental modules

The following are out of scope regardless of build configuration:
`mod_bucketeer`, `mod_dumpio`, `mod_firehose`, `mod_log_debug`,
`mod_echo`, `mod_dialup`, `mod_noloris`, `mod_serf`, and all modules
under `modules/examples` and `modules/test`.
