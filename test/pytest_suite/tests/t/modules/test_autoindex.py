r"""Translated from t/modules/autoindex.t -- mod_autoindex sorting/display.

Generates a directory of files with controlled sizes and mtimes, then for every
combination of FancyIndexing on/off, IndexOrderDefault Ascending/Descending,
sort component Name/Date/Size, and explicit ?C=&O= query overrides, fetches the
directory index and verifies the HTML head, the file list in the expected sort
order, and the footer.

Perl original: plan tests => 84, ['autoindex'];
"""

import os
import re

import pytest

from apache_pytest import need_module

README = "autoindex test README"
FILE_PREFIX = "ai-test"
URI_PREFIX = "/modules/autoindex/htaccess"
URI = URI_PREFIX + "/"

# name -> (size, mtime epoch)
FILE = {
    "README": (len(README), 998932210),
    "txt": (5, 998934398),
    "jpg": (15, 998936491),
    "gif": (1568, 998932291),
    "html": (9815, 922934391),
    "doc": (415, 998134391),
    "gz": (1, 998935991),
    "tar": (1009845, 997932391),
    "php": (913515, 998434391),
}


def _perl_split_lines(s):
    """Split on \\n dropping trailing empty fields, like Perl's ``split /\\n/``."""
    parts = s.split("\n")
    while parts and parts[-1] == "":
        parts.pop()
    return parts


def _dir(http):
    return os.path.join(http.vars("documentroot"), "modules", "autoindex", "htaccess")


def _htaccess(http):
    return os.path.join(_dir(http), ".htaccess")


def _create_content(http):
    d = _dir(http)
    os.makedirs(d, exist_ok=True)
    for name, (size, date) in FILE.items():
        if name in ("README", ".htaccess"):
            fpath = os.path.join(d, name)
        else:
            fpath = os.path.join(d, f"{FILE_PREFIX}.{name}")
        with open(fpath, "w") as f:
            f.write(README if name == "README" else "x" * size)
        os.utime(fpath, (date, date))


def _destroy_content(http):
    d = _dir(http)
    for name in FILE:
        fpath = os.path.join(d, name if name in ("README", ".htaccess")
                             else f"{FILE_PREFIX}.{name}")
        try:
            os.unlink(fpath)
        except OSError:
            pass


def _write_htaccess(http, content):
    with open(_htaccess(http), "w") as f:
        f.write(content)
    # add/update .htaccess to FILE (date, size) like the Perl test
    st = os.stat(_htaccess(http))
    FILE[".htaccess"] = (st.st_size, st.st_mtime)


def _sorted_files(c, o):
    keys = [k for k in FILE]
    if o.upper() == "A":
        if c.upper() == "N":
            return sorted(keys)
        if c.upper() == "S":
            return sorted(keys, key=lambda k: FILE[k][0])
        if c.upper() == "M":
            return sorted(keys, key=lambda k: FILE[k][1])
    else:
        if c.upper() == "N":
            return sorted(keys, reverse=True)
        if c.upper() == "S":
            return sorted(keys, key=lambda k: FILE[k][0], reverse=True)
        if c.upper() == "M":
            return sorted(keys, key=lambda k: FILE[k][1], reverse=True)
    return None


def _html_head(http, hr):
    if http.have_min_apache_version("2.4.66"):
        doctype = ('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                   '"http://www.w3.org/TR/html4/strict.dtd">')
    else:
        doctype = '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">'
    return (doctype + "\n<html>\n <head>\n  <title>Index of "
            + URI_PREFIX + "</title>\n </head>\n <body>\n<h1>Index of "
            + URI_PREFIX + "</h1>\n")


def _ai_test(http, htconf, c, o, t_uri):
    hr = "<hr>"
    fancy = "FancyIndex" in htconf
    _write_htaccess(http, htconf)
    actual_body = http.GET_BODY(t_uri)

    if not fancy:
        c = "N"

    file_list = _sorted_files(c, o)
    assert file_list is not None, f"sort C={c} O={o}"

    sep = "&amp;"
    if re.search(r"\?C=.;", actual_body):
        sep = ";"
    if "<hr />" in actual_body:
        hr = "<hr />"

    html_head = _html_head(http, hr)

    if fancy:
        name_href = "C=N" + sep + "O=A"
        date_href = "C=M" + sep + "O=A"
        size_href = "C=S" + sep + "O=A"
        hrefs = [name_href, date_href, size_href]
        for i, href in enumerate(hrefs):
            if re.match(rf"^C={re.escape(c)}", href, re.IGNORECASE):
                if o.upper() == "D":
                    hrefs[i] = f"C={c}{sep}O=A"
                else:
                    hrefs[i] = f"C={c}{sep}O=D"
                break
        name_href, date_href, size_href = hrefs
        html_head += (
            f'<pre>      <a href="?{name_href}">Name</a>                    '
            f'<a href="?{date_href}">Last modified</a>      '
            f'<a href="?{size_href}">Size</a>  '
            f'<a href="?C=D{sep}O=A">Description</a>{hr}      '
            f'<a href="/modules/autoindex/">Parent Directory</a>'
            f'                             -   \n')
        html_foot = f"{hr}</pre>\n</body></html>\n"
    else:
        html_head += ('<ul><li><a href="/modules/autoindex/"> '
                      'Parent Directory</a></li>\n')
        html_foot = "</ul>\n</body></html>\n"

    exp_head = _perl_split_lines(html_head)
    actual = _perl_split_lines(actual_body)

    for i in range(len(exp_head)):
        a = actual[i].lower() if i < len(actual) else ""
        e = exp_head[i].lower()
        if a == e:
            continue
        return False, f"html head line {i}: expect {e!r} got {a!r}"
    # like the Perl loop, i now points one past the last head line
    i = len(exp_head)

    # file list verification
    e = 0
    while e < len(file_list) and i < len(actual):
        f = file_list[e]
        if fancy:
            if f in ("README", ".htaccess"):
                cmp_string = f'<a href="{f}">{f}</a>'
            else:
                cmp_string = f'<a href="{FILE_PREFIX}.{f}">{FILE_PREFIX}.{f}</a>'
        else:
            if f in ("README", ".htaccess"):
                cmp_string = f'<li><a href="{f}"> {f}</a></li>'
            else:
                cmp_string = (f'<li><a href="{FILE_PREFIX}.{f}"> '
                              f'{FILE_PREFIX}.{f}</a></li>')
        a = actual[i].lower()
        cs = cmp_string.lower()
        if re.search(re.escape(cs), a):
            e += 1
            i += 1
            continue
        return False, f"file list line {i}: expect {cs!r} got {a!r}"

    # footer
    foot = html_foot.split("\n")
    fe = 0
    while fe < len(foot) and foot[fe]:
        a = actual[i].lower() if i < len(actual) else ""
        if a != foot[fe].lower():
            return False, f"footer line {i}: expect {foot[fe]!r} got {a!r}"
        fe += 1
        i += 1

    return True, ""


@need_module("autoindex")
def test_autoindex(http):
    _create_content(http)
    try:
        for fancy in (0, 1):
            for order in ("Ascending", "Descending"):
                O = order[0]
                for component in ("Name", "Date", "Size"):
                    C = component[0]
                    if C == "D":
                        C = "M"
                    config = ""
                    if fancy:
                        config = "IndexOptions FancyIndexing\n"
                    config += f"IndexOrderDefault {order} {component}\n"

                    ok, msg = _ai_test(http, config, C, O, URI)
                    assert ok, f"default order [{config!r}]: {msg}"

                    for Cx in ("N", "M", "S"):
                        for Ox in ("A", "D"):
                            test_uri = f"{URI}?C={Cx}&O={Ox}"
                            ok, msg = _ai_test(http, config, Cx, Ox, test_uri)
                            assert ok, f"explicit C={Cx} O={Ox} [{config!r}]: {msg}"
    finally:
        _destroy_content(http)
        try:
            os.unlink(_htaccess(http))
        except OSError:
            pass
