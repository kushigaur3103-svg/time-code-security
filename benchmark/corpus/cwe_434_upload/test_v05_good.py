import os
from werkzeug.utils import secure_filename

filename = input("f: ")
safe = secure_filename(filename)
if safe:
    file.save(os.path.join(UPLOAD_DIR, safe))
else:
    abort(400)
