import tempfile

class TempStore:
    def __init__(self):
        self.handle = tempfile.NamedTemporaryFile(delete=False)

store = TempStore()
print(store.handle.name)
