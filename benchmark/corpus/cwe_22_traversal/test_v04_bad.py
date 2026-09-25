import os

class FileReader:
    def __init__(self, filename):
        self.path = f"/var/app/uploads/{filename}"

    def read(self):
        with open(self.path) as f:
            return f.read()

filename = input("filename: ")
print(FileReader(filename).read())
