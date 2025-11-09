#!/usr/bin/env python3
import os
import sys
from requestparser import get_request_params


forms, files = get_request_params()

status = '200 Ok'

# Test if the file was uploaded
if 'file' in files:
    fitem = files['file']
    # strip leading path from file name to avoid directory traversal attacks
    fname = os.path.basename(fitem.file_name)
    fpath = f'{os.environ["DOCUMENT_ROOT"]}/files/{fname}'
    fitem.save_to(fpath)
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

