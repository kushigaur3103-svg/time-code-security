import os

UPLOAD_DIR = "/var/app/uploads"

class FileReader:
    def __init__(self, filename):
        safe = os.path.basename(filename)
        self.path = os.path.normpath(os.path.join(UPLOAD_DIR, safe))
        if not self.path.startswith(UPLOAD_DIR):
            raise ValueError("Blocked")

    def read(self):
        with open(self.path) as f:
            return f.read()

filename = input("filename: ")
print(FileReader(filename).read())
