"""Translated from t/php/strings3.t -- need_php (printf format tests).

The Perl test compares line-by-line: first asserts the line counts match, then
for each line compares "[line]" of result vs expected. Expected output contains
Latin-1 characters, preserved verbatim.
"""

from apache_pytest import need_php, t_cmp

EXPECTED = 'printf test 1:simple string\nprintf test 2:42\nprintf test 3:3.333333\nprintf test 4:3.3333333333\nprintf test 5:2.50      \nprintf test 6:2.50000000\nprintf test 7:0000002.50\nprintf test 8:<                 foo>\nprintf test 9:<bar                 >\nprintf test 10: 123456789012345\nprintf test 10:<høyesterettsjustitiarius>\nprintf test 11: 123456789012345678901234567890\nprintf test 11:<      høyesterettsjustitiarius>\nprintf test 12:-12.34\nprintf test 13:  -12\nprintf test 14:@\nprintf test 15:10101010\nprintf test 16:aa\nprintf test 17:AA\nprintf test 18:        10101010\nprintf test 19:              aa\nprintf test 20:              AA\nprintf test 21:0000000010101010\nprintf test 22:00000000000000aa\nprintf test 23:00000000000000AA\nprintf test 24:abcde\nprintf test 25:gazonk\nprintf test 26:2 1\nprintf test 27:3 1 2\nprintf test 28:02  1\nprintf test 29:2   1\n'


@need_php()
def test_strings3(http):
    # strings3.php is an ISO-8859-1 file and printf echoes its bytes verbatim
    # (e.g. 0xF8 for 'ø'). FPM sends no response charset, so httpx's .text
    # guesses wrong; decode the raw body as latin-1 so each byte maps 1:1 to
    # the expected codepoint. The PHP output itself is unchanged from PHP4.
    result = http.GET("/php/strings3.php").content.decode("latin-1")
    res = result.split("\n")
    exp = EXPECTED.split("\n")
    # Perl split drops the trailing empty field; mirror that.
    if res and res[-1] == "":
        res = res[:-1]
    if exp and exp[-1] == "":
        exp = exp[:-1]
    assert len(res) == len(exp)
    for i in range(len(res)):
        assert t_cmp(f"[{res[i]}]", f"[{exp[i]}]"), f"test {i}"
