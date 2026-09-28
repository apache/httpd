"""Translated from t/modules/access.t -- mod_access (Order/Allow/Deny).

Rewrites <t_dir>/htdocs/modules/access/htaccess/.htaccess with every
combination of Order x Allow/Deny clauses and checks whether the index is
served (GET_OK, i.e. 200) per the access-control logic.

Perl original gated on ``\&need_access`` (the Order/Allow/Deny directives live
in mod_access_compat on 2.4); gated here with @need_module.
"""

import sys

import pytest

from apache_pytest import need_module

ORDERS = ["deny,allow", "allow,deny", "mutual-failure"]
URL = "/modules/access/htaccess/index.html"


def _localhost_clauses(http):
    localhost_name = http.vars("servername")
    remote_addr = http.vars("remote_addr") or "127.0.0.1"
    addr = remote_addr.split(".")
    addr1 = addr[0]
    addr2 = ".".join(addr[:2])
    clauses = [
        "all",
        localhost_name,
        remote_addr,
        addr2,
        f"{remote_addr}/255.255.0.0",
        f"{remote_addr}/16",
        "somewhere.else.com",
        "66.6.6.6",
    ]
    return clauses, addr1, localhost_name


def _explicit(clause, addr1, localhost_name):
    """True if the (host part of the) clause matches this client."""
    return (clause.startswith(addr1)
            or clause == localhost_name
            or clause == "all")


def _htaccess_path(http):
    import os
    return os.path.join(http.vars("t_dir"), "htdocs", "modules", "access",
                        "htaccess", ".htaccess")


def _write_htaccess(http, conf):
    with open(_htaccess_path(http), "w") as f:
        f.write(conf)


@pytest.mark.skipif(sys.platform == "win32",
                    reason="dual-stack localhost makes Allow/Deny unreliable")
@need_module("mod_access_compat")
def test_access(http):
    clauses, addr1, localhost_name = _localhost_clauses(http)

    def is_ok():
        return http.GET_RC(URL) == 200

    def allowed(host):
        return _explicit(host, addr1, localhost_name)

    for order in ORDERS:
        for allow in clauses:
            _write_htaccess(http, f"Order {order}\nAllow from {allow}\n")

            if order == "deny,allow":
                # Allowing by default: no Deny -> everything allowed.
                assert is_ok()
            else:
                if allowed(allow):
                    assert is_ok()
                else:
                    assert not is_ok()

            for deny in clauses:
                _write_htaccess(http, f"Order {order}\nDeny from {deny}\n")

                if order == "deny,allow":
                    # Allowing by default.
                    if allowed(deny):
                        assert not is_ok()
                    else:
                        assert is_ok()
                else:
                    # Denying by default: no Allow -> everything denied.
                    assert not is_ok()

                _write_htaccess(
                    http, f"Order {order}\nAllow from {allow}\nDeny from {deny}\n")

                if order == "deny,allow":
                    if allowed(allow):
                        assert is_ok()
                    elif allowed(deny):
                        assert not is_ok()
                    else:
                        assert is_ok()
                else:
                    if allowed(deny):
                        assert not is_ok()
                    elif allowed(allow):
                        assert is_ok()
                    else:
                        assert not is_ok()
