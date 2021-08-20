#!/usr/bin/env python3
import cgi, os
import cgitb
cgitb.enable()

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
    fileitem = form['file']
    # strip leading path from file name to avoid directory traversal attacks
    fn = os.path.basename(fileitem.filename)
    f = open(('%s/files/%s' % (os.environ["DOCUMENT_ROOT"], fn)), 'wb');
    f.write(fileitem.file.read())
    f.close()
    message = "The file %s was uploaded successfully" % (fn)
    print("Status: 201 Created")
    print("Content-Type: text/html")
    print("Location: %s://%s/files/%s" % (os.environ["REQUEST_SCHEME"], os.environ["HTTP_HOST"], fn))
    print("")
    print("<html><body><p>%s</p></body></html>" % (message))
        
elif 'remove' in form:
    remove = form['remove'].value
    try:
        fn = os.path.basename(remove)
        os.remove('./files/' + fn)
        message = 'The file "' + fn + '" was removed successfully'
    except OSError as e:
        message = 'Error removing ' + fn + ': ' + e.strerror
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

