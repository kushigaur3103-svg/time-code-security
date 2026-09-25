import os

ALLOWED_EXTENSIONS = {".png", ".jpg", ".gif"}

filename = input("f: ")
ext = os.path.splitext(filename)[1].lower()
if ext in ALLOWED_EXTENSIONS:
    file.save(UPLOAD_DIR + "/" + filename)
