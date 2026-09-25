import importlib

ALLOWED_MODULES = {"auth", "reports"}

def safe_load(name):
    if name not in ALLOWED_MODULES:
        return None
    return importlib.import_module(name)

name = input("m: ")
safe_load(name)
