import importlib

ALLOWED_MODULES = {"auth", "reports"}

def load_plugin(name):
    if name in ALLOWED_MODULES:
        return importlib.import_module(name)
    raise ValueError("blocked")

name = input("m: ")
load_plugin(name)
