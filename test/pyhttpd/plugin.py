"""Command-line options for the test suites under test/.

Registered here, in a plugin the root conftest loads, rather than in the
conftests of modules/ or pytest_suite/: pytest only sees options from conftests
on the invocation path, so options defined in a subdirectory conftest are
"unrecognized" when pytest is run from test/ with no path arguments. A single
registration point also settles the options both suites share (--httpd, --conf),
since pytest rejects a duplicate addoption.

It also settles, once and before anything is collected, which httpd the
session tests: see pyhttpd.build.resolve_build.
"""
import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    from .build import TargetError, resolve_build
    try:
        resolve_build(config)
    except TargetError as exc:
        raise pytest.UsageError(f"httpd under test: {exc}") from exc


def pytest_addoption(parser):
    # modules/ (pyhttpd)
    parser.addoption("--repeat", action="store", type=int, default=1,
                     help='Number of times to repeat each test')
    parser.addoption("--all", action="store_true")
    parser.addoption("--archive", action="store", default=None,
                     help='Archive the server dir after each test package '
                          'to the specified folder')

    group = parser.getgroup("httpd")
    group.addoption("--base-port", action="store", type=int, default=None,
                    help="modules/: listen on this port and the next four instead of "
                    "free ports picked per test environment")
    group.addoption("--fixed-ports", action="store_true", default=False,
                    help="modules/: listen on the ports of the build's config.ini "
                    "(5001 ...) instead of free ports")
    group.addoption("--dynamic-ports", action="store_true", default=False,
                    help="modules/: free ports; this is the default, the option is "
                    "only kept for existing scripts")
    # shared by both suites
    group.addoption("--httpd", action="store", default=None,
                    help="path to httpd binary (modules/: used to derive prefix, "
                    "version, etc.; pytest_suite: default is derived from --apxs)")
    group.addoption("--conf", action="store", default=None,
                    help="path to the installed httpd.conf, for LoadModule discovery "
                    "(default: the one of --apxs; needed where apxs is not, e.g. "
                    "on Windows)")
    # pytest_suite
    group.addoption("--apxs", action="store", default=None, help="path to apxs")
    group.addoption(
        "--defines",
        action="store",
        default="",
        help="space-separated extra -D defines (e.g. 'LDAP')",
    )
    group.addoption(
        "--php-fpm",
        action="store",
        default=None,
        help="path to a php-fpm binary; enables the t/php tests via mod_proxy_fcgi "
        "(any version/location -- the path is the only PHP-specific input)",
    )
    group.addoption(
        "--php-fpm-port",
        action="store",
        type=int,
        default=8999,
        help="TCP port for the managed php-fpm pool (default 8999)",
    )
    group.addoption(
        "--clean-modules",
        action="store_true",
        default=False,
        help="remove all compiled C-module artifacts before building (emulate make clean)",
    )
    group.addoption(
        "--prefix",
        action="store",
        default=None,
        help="server install prefix for resolving relative module paths "
        "(default: derived from --conf path)",
    )
    group.addoption(
        "--with-perl",
        action="store",
        default=None,
        help="path to the perl interpreter for generated scripts and "
        "rewrite prg-maps (default: /usr/bin/perl or APACHE_TEST_PERL env)",
    )
