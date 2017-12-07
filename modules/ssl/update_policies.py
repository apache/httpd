#!/usr/bin/env python

import json
import os
import sys

from httplib import HTTPSConnection

# The location were Mozilla defines the *current* TLS Security in JSON format
#
MOZ_TLS_CONF_SERVER = "statics.tls.security.mozilla.org"
MOZ_TLS_CONF_PATH   = "/server-side-tls-conf.json"
MOZ_TLS_CONF_URL    = "https://%s%s" % (MOZ_TLS_CONF_SERVER, MOZ_TLS_CONF_PATH)

# The version we already know. Accept nothing less.
#
MOZ_TLS_CONF_VERSION_MIN = 4.0

# keys inside the JSON document
#
KEY_CONF         = 'configurations'
KEY_HREF         = 'href'
KEY_OSSL_CIPHERS = 'openssl_ciphersuites'
KEY_TLS_VERSIONS = 'tls_versions'
KEY_VERSION      = 'version'

# TLS Versions we know how to handle
#
TLS_VERSIONS     = {
    'TLSv1.2' : "SSL_PROTOCOL_TLSV1_2",
    'TLSv1.1' : "SSL_PROTOCOL_TLSV1_1",
    'TLSv1'   : "SSL_PROTOCOL_TLSV1",
    'SSLv3'   : "SSL_PROTOCOL_CONSTANTS_SSLV3",
}
TLS_1_X_VERSIONS = [ 'TLSv1.2' ]

# the Security configurations to extract
POLICY_NAMES = [ 'modern', 'intermediate', 'old' ]


def fail(msg):
    sys.stderr.write(msg)
    sys.exit(1)


def proto_string(tls_version):
    if tls_version in TLS_VERSIONS:
        return TLS_VERSIONS[tls_version]
    fail("Unknown TLS protocol '%s'" % tls_version)
    

def proto_conf(tls_versions):
    if len(TLS_VERSIONS) < len(tls_versions):
        fail("more TLS versions used than we know: %s" % tls_versions)
    if len(tls_versions) == 1:
        return proto_string(tls_versions[0])
    missing = []
    for tls in TLS_VERSIONS:
        if not tls in tls_versions:
            missing.append(proto_string(tls))
    if len(missing):
        return "(SSL_PROTOCOL_ALL & ~(%s))" % "|".join(missing)
    return "SSL_PROTOCOL_ALL"


# return an #ifdef required for a policy or None
#
def required_ifdef(conf):
    for tlsv in conf[KEY_TLS_VERSIONS]:
        # if it has a non-1_X protocol, it works without OpenSSL 1.0.2
        if not tlsv in TLS_1_X_VERSIONS:
            return None
    return "HAVE_TLSV1_X"
    

def getPolicyDef():
    c = HTTPSConnection(MOZ_TLS_CONF_SERVER)
    c.request('GET', MOZ_TLS_CONF_PATH)
    data = c.getresponse().read()
    c.close()
    return data


def printPolicies(doc):
    print "#define SSL_POLICY_MOZILLA_VERSION %s" % doc[KEY_VERSION]
    print ""
    for pname in POLICY_NAMES:
        prefix = "SSL_POLICY_%s" % pname.upper()
        if not pname in doc[KEY_CONF]:
            vars[prefix] = 0
            continue
        p = doc[KEY_CONF][pname]
        
        ifdef = required_ifdef(p)
        if ifdef:
            print "#ifdef %s" % ifdef
            
        print "#define %s    1" % prefix
        print "#define %s_CIPHERS \"%s\"" % (prefix, p[KEY_OSSL_CIPHERS])
        print "#define %s_PROTOCOLS %s" % (prefix, proto_conf(p[KEY_TLS_VERSIONS]))
        
        if ifdef:
            print "#else /* ifdef %s */" % ifdef
            print "#define %s    0" % prefix
            print "#endif /* ifdef %s, else part */" % ifdef
        print ""


def main(argv):
    data = getPolicyDef()
    doc = json.loads(data)
    
    if MOZ_TLS_CONF_URL != doc[KEY_HREF]:
        fail("ERROR: Unexpected href in policy document: %s\n" % doc[KEY_HREF])
    if doc[KEY_VERSION] < MOZ_TLS_CONF_VERSION_MIN:
        fail("ERROR: Expected at least version %s, but policy document has %s\n" \
            % (MOZ_TLS_CONF_VERSION_MIN, doc[KEY_VERSION]))
    
    if 1 == len(argv):
        printPolicies(doc)
    elif 2 == len(argv):
        with open(argv[1]) as f:
            for line in f:
                if line == "@MOZILLA_SECURITY_POLICIES@\n":
                    printPolicies(doc)
                else:
                    sys.stdout.write(line)
    else:
        fail("usage: %s [file] \nDownload and print/replace the Mozilla TLS Security policies" % argv[0])
    
    
if __name__ == "__main__":
    main(sys.argv)
