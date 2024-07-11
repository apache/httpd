#!/usr/bin/env python3
import os
import sys
from urllib import parse
import multipart # https://github.com/andrew-d/python-multipart (`apt install python3-multipart`)
import shutil


try:  # Windows needs stdio set for binary mode.
    import msvcrt

    msvcrt.setmode(0, os.O_BINARY)  # stdin  = 0
    msvcrt.setmode(1, os.O_BINARY)  # stdout = 1
except ImportError:
    pass


class FileItem:

    def __init__(self, mparse_item):
        self.item = mparse_item

    @property
    def file_name(self):
        return os.path.basename(self.item.file_name.decode())

    def save_to(self, destpath: str):
        fsrc = self.item.file_object
        fsrc.seek(0)
        with open(destpath, 'wb') as fd:
            shutil.copyfileobj(fsrc, fd)


def get_request_params():
    oforms = {}
    ofiles = {}
    if "REQUEST_URI" in os.environ:
        qforms = parse.parse_qs(parse.urlsplit(os.environ["REQUEST_URI"]).query)
        for name, values in qforms.items():
            oforms[name] = values[0]
    if "CONTENT_TYPE" in os.environ:
        ctype = os.environ["CONTENT_TYPE"]
        if ctype == "application/x-www-form-urlencoded":
            s = sys.stdin.read()
            qforms = parse.parse_qs(s)
            for name, values in qforms.items():
                oforms[name] = values[0]
        elif ctype.startswith("multipart/"):
            def on_field(field):
                oforms[field.field_name.decode()] = field.value.decode()
            def on_file(file):
                ofiles[file.field_name.decode()] = FileItem(file)
            multipart.parse_form(headers={"Content-Type": ctype},
                                 input_stream=sys.stdin.buffer,
                                 on_field=on_field, on_file=on_file)
    return oforms, ofiles

