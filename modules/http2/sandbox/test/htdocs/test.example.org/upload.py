#!/usr/bin/env python
import cgi, os
import cgitb; cgitb.enable()

status = '200 Ok'

try: # Windows needs stdio set for binary mode.
    import msvcrt
    msvcrt.setmode (0, os.O_BINARY) # stdin  = 0
    msvcrt.setmode (1, os.O_BINARY) # stdout = 1
except ImportError:
    pass

form = cgi.FieldStorage()

# Test if the file was uploaded
if 'file' in form:
    # A nested FieldStorage instance holds the file
    fileitem = form['file']
    
    # strip leading path from file name to avoid directory traversal attacks
    fn = os.path.basename(fileitem.filename)
    open('./files/' + fn, 'wb').write(fileitem.file.read())
    message = 'The file "' + fn + '" was uploaded successfully'

elif 'remove' in form:
    remove = form['remove'].value
    try:
        fn = os.path.basename(remove)
        os.remove('./files/' + fn)
        message = 'The file "' + fn + '" was removed successfully'
    except OSError, e:
        message = 'Error removing ' + fn + ': ' + e.strerror
        status = '404 File Not Found'
else:
    message = '''\
        Upload File<form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button></form>
        '''

print "Status: %s" % (status,)
print """\
    Content-Type: text/html\n
    <html><body>
    <p>%s</p>
    </body></html>""" % (message,)
