import os
from werkzeug.utils import secure_filename

filename = input("f: ")
safe = secure_filename(filename)
file.save(os.path.join(UPLOAD_DIR, safe))
