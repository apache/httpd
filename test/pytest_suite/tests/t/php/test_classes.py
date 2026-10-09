"""Translated from t/php/classes.t -- need_php; whitespace stripped before compare.

The Perl test strips all whitespace from both expected and result before
comparing (s/\\s//g), so we do the same here.
"""

import re

from apache_pytest import need_php

EXPECTED = 'User information\n----------------\n\nFirst name:    Zeev\nFamily name:    Suraski\nAddress:    Ben Gourion 3, Kiryat Bialik, Israel\nPhone:    \t+972-4-8713139\n\n\nUser information\n----------------\n\nFirst name:    Andi\nFamily name:    Gutmans\nAddress:    Haifa, Israel\nPhone:    \t+972-4-8231621\n\n\nUser information\n----------------\n\nFirst name:    Andi\nFamily name:    Gutmans\nAddress:    Haifa, Israel\nPhone:    \t+972-4-8231621\n\n\nUser information\n----------------\n\nFirst name:    Andi\nFamily name:    Gutmans\nAddress:    New address...\nPhone:    \t+972-4-8231621\n\n\n'


@need_php()
def test_classes(http):
    result = http.GET_BODY("/php/classes.php")
    expected = re.sub(r"\s", "", EXPECTED)
    result = re.sub(r"\s", "", result)
    assert result == expected
