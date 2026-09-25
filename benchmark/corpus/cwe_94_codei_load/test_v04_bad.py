import importlib

class Loader:
    def __init__(self, m):
        self.module = m

    def load(self):
        importlib.import_module(self.module)

name = input("m: ")
Loader(name).load()
