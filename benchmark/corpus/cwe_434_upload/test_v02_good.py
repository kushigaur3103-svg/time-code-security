import os
from werkzeug.utils import secure_filename

def store_upload(upload):
    safe = secure_filename(upload.filename)
    upload.save(os.path.join(UPLOAD_DIR, safe))

store_upload(request.files["file"])
