import importlib

ALLOWED_MODULES = {"auth", "reports"}

name = input("m: ")
if name not in ALLOWED_MODULES:
    raise ValueError("blocked")
mod = importlib.import_module(name)
