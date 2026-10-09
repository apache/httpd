"""Translated from t/php/all.t -- need_php; trivial "skip whole dir unless PHP".

The Perl test plans one trivial passing assertion (``ok 1``) gated on need_php,
so the entire php/ directory is skipped when mod_php is absent.
"""

from apache_pytest import need_php


@need_php()
def test_all():
    assert True
