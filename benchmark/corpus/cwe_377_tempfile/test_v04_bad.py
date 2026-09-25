import tempfile

class TempStore:
    def __init__(self):
        self.path = tempfile.mktemp()

store = TempStore()
print(store.path)
