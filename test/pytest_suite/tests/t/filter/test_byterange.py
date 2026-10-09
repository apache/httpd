"""Translated from t/filter/byterange.t -- PR61860 out-of-range byterange.

Perl original (plan tests => 2, need mod_headers + min 2.5.0):
    push @headers, "Range" => "bytes=6549-";
    my $response = GET($uri, @headers);
    ok t_cmp($response->code, 416, "Out of Range bytes in header should return HTTP 416");
    my @duplicate_header = $response->header("TestDuplicateHeader");
    ok t_cmp(@duplicate_header, 1, "Headers should not be duplicated on HTTP 416 responses");
"""

from apache_pytest import need_min_apache_version, need_module, t_cmp

URI = "/modules/filter/byterange/pr61860/test.html"


@need_module("mod_headers")
@need_min_apache_version("2.5.0")
def test_byterange_out_of_range(http):
    response = http.GET(URI, headers={"Range": "bytes=6549-"})
    assert t_cmp(response.status_code, 416), (
        "Out of Range bytes in header should return HTTP 416"
    )
    # The header must appear exactly once (not duplicated) on a 416 response.
    duplicate_header = response.headers.get_list("TestDuplicateHeader")
    assert t_cmp(len(duplicate_header), 1), (
        "Headers should not be duplicated on HTTP 416 responses"
    )
