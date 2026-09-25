import importlib

name = input("m: ")
if legacy:
    importlib.import_module(f"legacy.{name}")
else:
    importlib.import_module(name)
