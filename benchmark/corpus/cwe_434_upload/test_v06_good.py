import os
from werkzeug.utils import secure_filename

upload = request.files["file"]
name = secure_filename(upload.filename)
dest = os.path.join(UPLOAD_DIR, name)
upload.save(dest)
