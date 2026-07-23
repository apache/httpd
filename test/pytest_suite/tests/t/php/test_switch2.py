"""Translated from t/php/switch2.t -- need_php."""

from apache_pytest import need_php

EXPECTED = 'In branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\nIn branch 1\nInner default...\nblah=100\n'


@need_php()
def test_switch2(http):
    result = http.GET_BODY("/php/switch2.php")
    assert result == EXPECTED
