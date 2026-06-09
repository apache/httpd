r"""Translated from t/security/CVE-2009-1195.t -- mod_include Options inheritance.

Perl original (plan tests => 221, need 'include', need_min_apache_version('2.2')):
    Apache::TestRequest::module('mod_include'); # use this module's port
    For each of 121 ssi-exec/<n> URLs, GET it and assert the response code; for
    most also assert the body shows SSI was/was not evaluated and whether exec
    was permitted. See the .t file for the per-case Options/AllowOverride context.

Body expectations:
    '[an error occurred while processing this directive]' -> SSI ran, exec denied
    re '--#exec cgi='                                     -> SSI not evaluated (echoed)
    'perl cgi'                                            -> SSI ran, exec permitted

The 'perl cgi' cases exercise SSI #exec cgi and require a working CGI module
(mod_cgi/mod_cgid).
"""

import re

import pytest

from apache_pytest import need_module, t_cmp

CASES = [

    {'url': '/modules/include/ssi-exec/1/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/2/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/3/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/4/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/5/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/6/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/7/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/8/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/9/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/10/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/11/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/12/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/13/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/14/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/15/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/16/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/17/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/18/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/19/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/20/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/21/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/22/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/23/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/24/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/25/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/26/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/27/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/28/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/29/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/30/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/31/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/32/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/33/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/34/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/35/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/36/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/37/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/38/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/39/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/40/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/41/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/42/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/43/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/44/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/45/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/46/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/47/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/48/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/49/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/50/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/51/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/52/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/53/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/54/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/55/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/56/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/57/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/58/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/59/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/60/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/61/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/62/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/63/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/64/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/65/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/66/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/67/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/68/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/69/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/70/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/71/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/72/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/73/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/74/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/75/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/76/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/77/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/78/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/79/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/80/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/81/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/82/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/83/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/84/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/85/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/86/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/87/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/88/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/89/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/90/exec.shtml', 'code': 500},
    {'url': '/modules/include/ssi-exec/91/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/92/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/93/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/94/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/95/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/96/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/97/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/98/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/99/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/100/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/101/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/102/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/103/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/104/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/105/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/106/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/107/exec.shtml', 'code': 200, 'body': '[an error occurred while processing this directive]', 'body_re': False},
    {'url': '/modules/include/ssi-exec/108/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/109/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/110/exec.shtml', 'code': 200, 'body': '--\\#exec cgi=', 'body_re': True},
    {'url': '/modules/include/ssi-exec/111/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/112/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/113/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/114/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/115/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/116/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/117/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/118/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/119/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/120/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
    {'url': '/modules/include/ssi-exec/121/subdir/exec.shtml', 'code': 200, 'body': 'perl cgi', 'body_re': False},
]


@need_module("include")
@pytest.mark.parametrize("case", CASES, ids=lambda c: c["url"])
def test_cve_2009_1195(http, case):
    if not http.have_min_apache_version("2.2"):
        pytest.skip("needs httpd >= 2.2")
    http.module("mod_include")
    r = http.GET(case["url"])
    assert t_cmp(r.status_code, case["code"]), f"code for {case['url']}"
    if "body" in case:
        body = r.text.rstrip("\n")
        expected = re.compile(case["body"]) if case["body_re"] else case["body"]
        assert t_cmp(body, expected), f"body for {case['url']}"
