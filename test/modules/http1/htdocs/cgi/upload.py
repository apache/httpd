#!/usr/bin/env python3
import os
import sys
from urllib import parse
import multipart # https://github.com/andrew-d/python-multipart (`apt install python3-multipart`)


try:  # Windows needs stdio set for binary mode.
    import msvcrt

    msvcrt.setmode(0, os.O_BINARY)  # stdin  = 0
    msvcrt.setmode(1, os.O_BINARY)  # stdout = 1
except ImportError:
    pass


def get_request_params():
    oforms = {}
    ofiles = {}
    if "REQUEST_URI" in os.environ:
        qforms = parse.parse_qs(parse.urlsplit(os.environ["REQUEST_URI"]).query)
        for name, values in qforms.items():
            oforms[name] = values[0]
    if "HTTP_CONTENT_TYPE" in os.environ:
        ctype = os.environ["HTTP_CONTENT_TYPE"]
        if ctype == "application/x-www-form-urlencoded":
            qforms = parse.parse_qs(parse.urlsplit(sys.stdin.read()).query)
            for name, values in qforms.items():
                oforms[name] = values[0]
        elif ctype.startswith("multipart/"):
            def on_field(field):
                oforms[field.field_name] = field.value
            def on_file(file):
                ofiles[field.field_name] = field.value
            multipart.parse_form(headers={"Content-Type": ctype}, input_stream=sys.stdin.buffer, on_field=on_field, on_file=on_file)
    return oforms, ofiles


forms, files = get_request_params()

status = '200 Ok'

# Test if the file was uploaded
if 'file' in files:
    fitem = files['file']
    # strip leading path from file name to avoid directory traversal attacks
    fname = fitem.filename
    fpath = f'{os.environ["DOCUMENT_ROOT"]}/files/{fname}'
    fitem.save_as(fpath)
    message = "The file %s was uploaded successfully" % (fname)
    print("Status: 201 Created")
    print("Content-Type: text/html")
    print("Location: %s://%s/files/%s" % (os.environ["REQUEST_SCHEME"], os.environ["HTTP_HOST"], fname))
    print("")
    print("<html><body><p>%s</p></body></html>" % (message))

elif 'remove' in forms:
    remove = forms['remove']
    try:
        fname = os.path.basename(remove)
        os.remove('./files/' + fname)
        message = 'The file "' + fname + '" was removed successfully'
    except OSError as e:
        message = 'Error removing ' + fname + ': ' + e.strerror
        status = '404 File Not Found'
    print("Status: %s" % (status))
    print("""
Content-Type: text/html

<html><body>
<p>%s</p>
</body></html>""" % (message))

else:
    message = '''\
        Upload File<form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button></form>
        '''
    print("Status: %s" % (status))
    print("""\
Content-Type: text/html

<html><body>
<p>%s</p>
</body></html>""" % (message))

