r"""Translated from t/modules/authz_core.t -- RequireAll/RequireAny + AuthzMerging.

Writes .htaccess files into nested directories combining Require directives
inside <RequireAll>/<RequireAny>/<RequireNone> containers with various
AuthMerging modes, then GETs each path with combinations of authenticated
users (Require group userN) and envvar grants (X-AllowedN => Require env
allowedN), asserting the resulting status code (200/401/403).

mod_authany overrides the 'user' provider, so the Perl test uses groups (group
name == user name == password) to stand in for user checks.

Perl original: plan tests => 168 + 14*24, need need_lwp, mod_authn_core,
mod_authz_core, mod_authz_host, mod_authz_groupfile, need_min_apache_version('2.3.6').
"""

import os
from itertools import permutations

import httpx

from apache_pytest import need_min_apache_version, need_module

BASIC1 = (
    "user1:NYSYdf7MU5KpU\n"
    "user2:KJ7Yxzr1VVzAI\n"
    "user3:xnpSvZ2iqti/c\n"
)
GROUPS1 = (
    "user1:user1\n"
    "user2:user2\n"
    "user3:user3\n"
)


def _write_files(http):
    root = http.vars("serverroot")
    with open(os.path.join(root, "basic1"), "w") as f:
        f.write(BASIC1)
    with open(os.path.join(root, "groups1"), "w") as f:
        f.write(GROUPS1)


def _write_htaccess(http, path, merging, container, *requires):
    need_auth = False
    content = ""
    if merging:
        content += f"AuthMerging {merging}\n"
    if container:
        content += f"<Require{container}>\n"
    for req in requires:
        req = str(req)
        not_ = ""
        if req.startswith("!"):
            req = req[1:]
            not_ = "not "
        if "all" in req:
            content += f"Require {not_}{req}\n"
        elif "user" in req:
            # 'group' is correct (mod_authany overrides 'user' provider)
            content += f"Require {not_}group {req}\n"
            need_auth = True
        else:
            content += f"Require {not_}env allowed{req}\n"
    if container:
        content += f"</Require{container}>\n"
    if need_auth:
        content += "AuthType basic\nAuthName basic1\n"
        content += "AuthUserFile basic1\nAuthGroupFile groups1\n"

    fpath = os.path.join(http.vars("documentroot"), "authz_core", path, ".htaccess")
    os.makedirs(os.path.dirname(fpath), exist_ok=True)
    with open(fpath, "w") as f:
        f.write(content)


def _check(http, rc, path, *args):
    auth = None
    headers = {}
    for e in args:
        e = str(e)
        if "user" in e:
            auth = httpx.BasicAuth(e, e)
        else:
            headers[f"X-Allowed{e}"] = "yes"
    r = http.GET(f"/authz_core/{path}", auth=auth, headers=headers)
    assert r.status_code == rc, (
        f"got {r.status_code}, expected {rc} [{path} {args}]")


@need_module("authn_core", "authz_core", "authz_host", "authz_groupfile")
@need_min_apache_version("2.3.6")
def test_authz_core(http):
    _write_files(http)
    w = lambda *a: _write_htaccess(http, *a)  # noqa: E731
    c = lambda *a: _check(http, *a)  # noqa: E731

    w("a/", None, None)
    c(200, "a/")
    c(200, "a/", 1)
    c(200, "a/", 2)
    c(200, "a/", 1, 2)
    c(200, "a/", 3)

    w("a/", None, None, "user1")
    c(401, "a/")
    c(200, "a/", "user1")
    c(401, "a/", "user2")

    w("a/", None, "Any", 1, 2)
    c(403, "a/")
    c(200, "a/", 1)
    c(200, "a/", 2)
    c(200, "a/", 1, 2)
    c(403, "a/", 3)
    w("a/b/", None, "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Off", "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Or", "Any", 2, 3)
    c(403, "a/b/")
    c(200, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "And", "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 1, 2)
    c(200, "a/b/", 1, 3)
    c(200, "a/b/", 2, 3)
    w("a/b/", None, "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Off", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Or", "All", 3, 4)
    c(403, "a/b/")
    c(200, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 2, 3)
    c(200, "a/b/", 3, 4)
    c(403, "a/b/", 3)
    c(403, "a/b/", 4)
    w("a/b/", "And", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 1, 2)
    c(403, "a/b/", 1, 3)
    c(200, "a/b/", 2, 3)

    w("a/", None, "All", 1, "!2")
    c(403, "a/")
    c(200, "a/", 1)
    c(403, "a/", 2)
    c(403, "a/", 1, 2)
    c(403, "a/", 3)
    w("a/b/", None, "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Off", "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Or", "Any", 3, 4)
    c(403, "a/b/")
    c(200, "a/b/", 1)
    c(403, "a/b/", 1, 2)
    c(200, "a/b/", 1, 2, 3)
    c(200, "a/b/", 1, 2, 4)
    c(200, "a/b/", 4)
    w("a/b/", "And", "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 1, 2)
    c(200, "a/b/", 1, 3)
    c(403, "a/b/", 2, 3)
    # should not inherit AuthMerging And from a/b/
    w("a/b/c/", None, "Any", 4)
    c(403, "a/b/c/", 1, 3)
    c(200, "a/b/c/", 4)
    c(200, "a/b/c/", 1, 2, 4)
    w("a/b/", None, "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Off", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Or", "All", 3, 4)
    c(403, "a/b/")
    c(200, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 2, 3)
    c(200, "a/b/", 3, 4)
    c(403, "a/b/", 3)
    c(403, "a/b/", 4)
    w("a/b/", "And", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 1, 2)
    c(403, "a/b/", 1, 3)
    c(403, "a/b/", 2, 3)

    w("a/", None, "All", 1, 2)
    c(403, "a/")
    c(403, "a/", 1)
    c(403, "a/", 2)
    c(200, "a/", 1, 2)
    w("a/b/", None, "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Off", "Any", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(200, "a/b/", 2)
    c(200, "a/b/", 3)
    w("a/b/", "Or", "Any", 3, 4)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(200, "a/b/", 1, 2)
    c(200, "a/b/", 3)
    c(200, "a/b/", 4)
    w("a/b/", "And", "Any", 3, 4)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 4)
    c(403, "a/b/", 1, 2)
    c(200, "a/b/", 1, 2, 3)
    c(200, "a/b/", 1, 2, 4)
    c(403, "a/b/", 1, 3, 4)
    w("a/b/", None, "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Off", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(200, "a/b/", 2, 3)
    c(403, "a/b/", 1, 3)
    w("a/b/", "Or", "All", 3, 4)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 4)
    c(403, "a/b/", 2, 3)
    c(200, "a/b/", 3, 4)
    c(200, "a/b/", 1, 2)
    w("a/b/", "And", "All", 2, 3)
    c(403, "a/b/")
    c(403, "a/b/", 1)
    c(403, "a/b/", 2)
    c(403, "a/b/", 3)
    c(403, "a/b/", 1, 2)
    c(403, "a/b/", 1, 3)
    c(403, "a/b/", 2, 3)
    c(200, "a/b/", 1, 2, 3)

    # all orders of a mix of user and non-user authz providers
    for p in permutations(["user1", "user2", 1, 2]):
        w("a/", None, "All", *p)
        c(403, "a/")
        c(403, "a/", 1)
        c(403, "a/", "user1")
        c(401, "a/", 1, 2)
        c(401, "a/", 1, 2, "user1")
        c(401, "a/", 1, 2, "user3")
        c(403, "a/", 1, "user1")

        w("a/", None, "Any", *p)
        c(401, "a/")
        c(200, "a/", 1)
        c(200, "a/", "user1")
        c(401, "a/", "user3")
        c(200, "a/", 1, 2)
        c(200, "a/", 1, "user1")
        c(200, "a/", 1, "user3")
