import importlib

ALLOWED_MODULES = {"auth", "reports"}

name = input("m: ")
if name in ALLOWED_MODULES:
    importlib.import_module(name)
