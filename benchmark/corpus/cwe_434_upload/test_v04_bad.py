class UploadHandler:
    def __init__(self, filename):
        self.filename = filename

    def store(self):
        file.save(self.filename)

UploadHandler(input("f: ")).store()
