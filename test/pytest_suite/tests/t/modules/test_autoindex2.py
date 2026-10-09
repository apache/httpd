"""Translated from t/modules/autoindex2.t -- mod_autoindex sub-dir handling.

Creates sub-dirs under <documentroot>/modules/autoindex2 (normal, password
protected, broken .htaccess), requests the listing, and checks which sub-dirs
appear. On Apache 2 the protected and broken dirs must NOT be listed.
"""

import os

from apache_pytest import need_module, t_cmp


def _setup(base_dir):
    os.makedirs(base_dir, exist_ok=True)

    os.makedirs(os.path.join(base_dir, "dir_normal"), exist_ok=True)

    prot_dir = os.path.join(base_dir, "dir_protected")
    os.makedirs(prot_dir, exist_ok=True)
    with open(os.path.join(prot_dir, "htpasswd"), "w") as f:
        f.write("nobody:HIoD8SxAgkCdQ")
    htaccess = (
        "AuthType Basic\n"
        'AuthName "Restricted Directory"\n'
        f"AuthUserFile {prot_dir}/htpasswd\n"
        "Require valid user\n"
    )
    with open(os.path.join(prot_dir, ".htaccess"), "w") as f:
        f.write(htaccess)

    broken_dir = os.path.join(base_dir, "dir_broken")
    os.makedirs(broken_dir, exist_ok=True)
    with open(os.path.join(broken_dir, ".htaccess"), "w") as f:
        f.write("This_is_a_broken_on_purpose_.htaccess_file")


@need_module("autoindex")
def test_autoindex2(http):
    documentroot = http.vars("documentroot")
    base_dir = os.path.join(documentroot, "modules", "autoindex2")
    base_uri = "/modules/autoindex2"

    _setup(base_dir)

    have_apache_2 = http.have_apache(2)
    # 1 == should appear in the listing, 0 == should not.
    dirs = {
        "dir_normal": 1,
        "dir_protected": 0 if have_apache_2 else 1,
        "dir_broken": 0 if have_apache_2 else 1,
    }

    res = http.GET_BODY(f"{base_uri}/")

    for d in sorted(dirs):
        found = 1 if d in res else 0
        should = "" if dirs[d] else "not "
        assert t_cmp(found, dirs[d]), f"{d} should {should}be listed"
