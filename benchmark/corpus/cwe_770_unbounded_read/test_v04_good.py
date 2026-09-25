class StreamReader:
    def __init__(self, f):
        self.f = f

    def ingest(self):
        data = self.f.read(65536)
        return len(data)
