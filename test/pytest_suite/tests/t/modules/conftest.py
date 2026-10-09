"""Module-local fixtures/setup for t/modules tests.

Apache::Test's TestRun sets ``$ENV{APACHE_TEST_HOSTNAME} = 'test.host.name'``
before launching httpd; several module configs ``PassEnv APACHE_TEST_HOSTNAME``
(e.g. the reverse-proxy CGI checks in proxy.t/proxy_balancer.t echo it back).

The Python framework's server launches httpd inheriting ``os.environ`` but does
not seed this variable. We set it here at collection time -- conftests are
imported before the session-scoped server fixture starts httpd, so the value is
present in the server's environment when it launches. (This mirrors the Perl
TestRun behaviour without modifying the framework core.)
"""

import os

os.environ.setdefault("APACHE_TEST_HOSTNAME", "test.host.name")
