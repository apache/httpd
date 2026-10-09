r"""Translated from t/ssl/extlookup.t.

Exercises mod_test_ssl's /test_ssl_ext_lookup handler (ssl_ext_lookup optional
function): GET ``?<OID>`` with the client_ok cert and assert the returned
certificate-extension value.

* 2.16.840.1.113730.1.13 (nsComment)          -> "This Is A Comment"
* 1.3.6.1.4.1.18060.12.0 (custom, >= 2.4.0)   -> "Lemons"
"""

from apache_pytest import need_min_apache_version, need_module, need_ssl
from apache_pytest.testapi import t_cmp


@need_ssl()
@need_module("test_ssl")
@need_min_apache_version("2.1")
def test_ext_lookup(http):
    http.scheme("https")

    exts = {"2.16.840.1.113730.1.13": "This Is A Comment"}
    if http.have_min_apache_version("2.4.0"):
        exts["1.3.6.1.4.1.18060.12.0"] = "Lemons"

    for oid in sorted(exts):
        r = http.GET(f"/test_ssl_ext_lookup?{oid}", cert="client_ok")
        assert t_cmp(r.status_code, 200), f"ssl_ext_lookup works for {oid}"
        assert t_cmp(r.text.rstrip("\n"), exts[oid]), f"Extension value match for {oid}"
