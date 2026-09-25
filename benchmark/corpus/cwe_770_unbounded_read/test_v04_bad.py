class StreamReader:
    def __init__(self, f):
        self.f = f

    def ingest(self):
        data = self.f.read()
        return len(data)
