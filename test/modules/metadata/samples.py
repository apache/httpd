# Sample file contents for content type detection tests.  Each is
# served without an extension, so mod_mime sets no type and the magic
# modules have to derive one from the content.  mod_mime_magic only
# applies its magic rules to files of at least 64 bytes, so samples
# meant to match a rule are padded past that.
import gzip
import os

SAMPLES = {
    "html": b"<html>\n<body>hello</body>\n</html>\n",
    "html-doctype": b"<!DOCTYPE html>\n<html><head><title>t</title></head>"
                    b"<body>hi</body></html>\n",
    # (no commas: libmagic 5.45 calls lines with a consistent number
    # of commas text/csv)
    "text": b"hello world this is plain ascii text\n"
            b"with a second line of a different length\n" * 2,
    "text-utf8": "café naïve résumé\n".encode() * 4,
    "text-latin1": b"caf\xe9 na\xefve\n" * 4,
    "csrc": b"#include <stdio.h>\n\nint main(int argc, char **argv)\n{\n"
            b"    printf(\"hi\\n\");\n    return 0;\n}\n",
    "json": b'{"a": 1, "b": [1, 2, 3], "c": {"d": "e", "f": "some more text"}}\n',
    "xml": b"<?xml version=\"1.0\"?>\n<root><a>1</a><b>2</b><c>3</c><d>4</d></root>\n",
    "rfc822": b"From: a@example.com\nTo: b@example.com\nSubject: hi there\n\n"
              b"the body of the message\n",
    "shell": b"#!/bin/sh\necho hi\necho there\necho this is a shell script\n"
             b"exit 0\n",
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
           b"\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1f\xf3\xffa"
           + b"\x00" * 64,
    "gif": b"GIF89a\x10\x00\x10\x00\x80\x00\x00" + b"\x00" * 64,
    "pdf": b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n",
    "gzip": gzip.compress(bytes(range(32, 127)) * 4, mtime=0),
    "elf": b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
           + b"\x02\x00\x3e\x00\x01\x00\x00\x00" + b"\x00" * 100,
    # deterministic bytes which libmagic reports as application/octet-stream
    "binary": bytes((i * 7919) % 256 for i in range(4096)),
    "empty": b"",
}


def write_samples(doc_dir):
    """Write every sample into doc_dir, plus png.txt (PNG content
    with a .txt extension)."""
    os.makedirs(doc_dir, exist_ok=True)
    for name, content in SAMPLES.items():
        with open(os.path.join(doc_dir, name), "wb") as f:
            f.write(content)
    with open(os.path.join(doc_dir, "png.txt"), "wb") as f:
        f.write(SAMPLES["png"])
