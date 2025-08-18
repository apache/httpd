
# Apache2 OpenSSL Encrypted Client Hello (ECH) integration.

> [!NOTE]
> This documentation probably doesn't belong here, nor as a single file, but
> may be useful to have in one place as we process the PR. TODO: find out where
> to put the various bits and pieces once those are stable.

ECH is specified in
[draft-ietf-tls-esni](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/).
This documentation assumes a basic familiarity with the ECH specification.

This build only supports ECH "shared-mode" where the apache2 instance does the
ECH decryption and also hosts both the ECH `public-name` and `backend` web
sites.  

## Build

> [!NOTE]
> ECH is not yet a part of an OpenSSL release, our current goal is that ECH be
> part of an OpenSSL 4.0 release in spring 2026. 

There is client and server ECH code in the OpenSSL ECH feature branch at
[https://github.com/openssl/openssl/tree/feature/ech](https://github.com/openssl/openssl/tree/feature/ech).
At present, ECH-enabling apache2 therefore requires building from source, using
the OpenSSL ECH feature branch.

To get and build the ECH feature branch:

```bash
$ cd /home/user/code
$ git clone https://github.com/openssl/openssl/
$ cd openssl
$ git checkout feature/ech
$ ./config -d 
...stuff...
$ make -j8
...stuff..
```

We next need the httpd fork and the Apache Portable Runtime (APR).  As
recommended, the APR stuff should be in a `srclib` sub-directory of the httpd
source directory.

```bash
    $ cd $HOME/code
    $ git clone https://github.com/sftcd/httpd
    $ cd httpd
    $ git checkout ECH-shared
    $ cd srclib
    $ git clone https://github.com/apache/apr.git
    $ cd ..
    $ ./buildconf
    ... stuff ...
```

And off we go with configure and make ...

```bash
    $ export CFLAGS="-I$HOME/code/openssl/include"
    $ export LDFLAGS="-L$HOME/code/openssl"
    $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl
    ... stuff ...
    $ make -j8
    ... stuff ...
```

## ECH Key Generation and Publication

In the remaining, we describe a configuration that uses `example.com` as the
ECH `public-name` and where `foo.example.com` is a web-site for which we want
ECH to be used, with both hosted on the same apache2 instance.

Using ECH requries that apache2 load an ECH key pair with a private value for ECH
decryption. Browsers will require that the public component of that key pair be
published in the DNS. With OpenSSL we generate and store that key pair in a PEM
formatted file as shown below.

To generate ECH PEM files, use the openssl binary produced by the build above
(which is `/home/user/code/openssl/apps/openssl`) to generate
an ECH key pair and store the result in a PEM file. You should also supply the
`public-name` required by the ECH protocol.

Key generation operations should be carried out under whatever local account is
used for apache2 configuration.

```bash
~# OSSL=/home/user/code/openssl/apps/openssl
~# mkdir -p /etc/apache2/echkeydir
~# chmod 700 /etc/apache2/echkeydir
~# cd /etc/apache2/echkeydir
~# $OSSL ech -public-name example.com -o example.com.pem.ech
~# cat example.com.pem.ech
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIJi22Im2rJ/lJqzNFZdGfsVfmknXAc8xz3fYPhD0Na5I
-----END PRIVATE KEY-----
-----BEGIN ECHCONFIG-----
AD7+DQA6QwAgACA8mxkEsSTp2xXC/RUFCC6CZMMgdM4x1iTWKu3EONjbMAAEAAEA
AQALZXhhbXBsZS5vcmcAAA==
-----END ECHCONFIG-----
```

> [!NOTE]
> The January 2025 lighttpd web server release included ECH and adopted a
> naming convention for ECH PEM files that their names ought end in `.ech`.
> This PR follows that covention.

The ECHConfig value then needs to be published in an HTTPS resource record in
the DNS, so as to be accessible as shown below:

```bash
$ dig +short HTTPS foo.example.com
1 . ech=AD7+DQA6QwAgACA8mxkEsSTp2xXC/RUFCC6CZMMgdM4x1iTWKu3EONjbMAAEAAEAAQALZXhhbXBsZS5vcmcAAA==
$ 
```

Various other fields may be included in an HTTPS resource record. For many
apache2 instances, existing methods for publishing DNS records may be used to
achieve the above.  In some cases, one might use [A well-known URI for
publishing service
parameters](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech)
designed to assist web servers in handling e.g. frequent ECH key rotation.

## Configuration

There's one new server-wide `SSLECHKeyDir` directive needed for ECH that
names the directory where ECH key pair files (names `*.ech`) are stored.
A configuration might therefore include:

```
...
# TLS stuff
SSLEngine On
SSLProtocol TLSv1.3
SSLECHKeyDir /etc/apache2/echkeydir
...

# virtual hosts
<VirtualHost *:443>
    SSLEngine On
    SSLProtocol TLSv1.3
    ServerName example.com
    DocumentRoot "/var/www/dir-example.com"
</VirtualHost>
<VirtualHost *:443>
    SSLEngine On
    SSLProtocol TLSv1.3
    ServerName foo.example.com
    DocumentRoot "/var/www/dir-foo.example.com"
</VirtualHost>
...
```

## Logs

After accessing `foo.example.com` and successfully using ECH, the `error.log`
should contain a line like:

```bash
[Fri Nov 24 16:41:57.863004 2023] [ssl:info] [pid 158960:tid 140277178160832] [client 127.0.0.1:53180] AH10240: ECH success outer_sni: example.com inner_sni: foo.example.com
```

And `access.log` should contain something like:

```bash
127.0.0.1 - - [24/Nov/2023:16:41:57 +0000] foo.example.com "GET /index.html HTTP/1.1" 200 "-" "-"
```

## CGI variables

The following variables that are now visible to PHP code, assuming
you have PHP enabled/configured for the apache2 instance:

- `SSL_ECH_STATUS` - `success` means that others also mean what they say
- `SSL_ECH_INNER_SNI` - has value that was encrypted in ECH (or `NONE`)
- `SSL_ECH_OUTER_SNI` - has value that was seen in plaintext SNI (or `NONE`)

## Code changes

- All code changes are within `modules/ssl` and are protected via `#ifdef
  HAVE_OPENSSL_ECH`.  That's defined in `ssl_private.h` if the included
`ssl.h` defines `SSL_OP_ECH_GREASE`.

- There're a bunch of changes to add the new `SSLECHKeyDir` directive that
  are mosly obvious.

- We load the keys from `SSLECHKeyDir` using the `load_echkeys()` function in
  `ssl_engine_init.c`. That also ECH-enables the `SSL_CTX` when keys are
  loaded, which triggers ECH decryption as needed.

> [!NOTE]
> `load_echkeys()` will include the public component all loaded keys in the ECH
> `retry-configs` in the fallback scenario. If desired, we could add a naming
> convention or additional configuration setting to distinguish which to
> include in `retry-configs` or not. For now, we assume that'd better be done
> in a subsequent PR, if experience shows the feature is really useful/needed.
> (We can envisage some odd deployments where that might be the case, but not
> clear those'd really happen - it'd seem to need loads of key pairs or else
> some that are never published in the DNS that we don't want to expose to
> random clients - neither seems compelling.)

- We add a callback to `SSL_CTX_ech_set_callback` also in `ssl_engine_init.c`.

- We add calls to set the `SSL_ECH_STATUS` etc. variables to the environment
(for PHP etc) in `ssl_engine_kernel.c` and also do the logging of ECH outcomes
(to the error log).

## Reloading ECH keys

Giving apache2 a command line argument of "-k graceful" causes a graceful reload
of the configuration, without dropping existing connections.

> [!NOTE]
> The ECH integration released by the lighttpd web server in January 2025
> allows configuration of a timer used to cause ECH PEM files to be reloaded if
> those have changed. This PR does not include that functionality but it could
> be added if desired, e.g. if regularly reloading the entire apache2
> configuration is considered undesirable. See the [lighttpd
> code](https://github.com/lighttpd/lighttpd1.4/blob/master/src/mod_openssl.c#L799)
> for details.

