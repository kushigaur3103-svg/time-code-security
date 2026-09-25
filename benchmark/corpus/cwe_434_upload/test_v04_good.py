import os
from uuid import uuid4

filename = input("f: ")
ext = os.path.splitext(filename)[1]
safe = uuid4().hex + ext
file.save(os.path.join(UPLOAD_DIR, safe))
