import importlib

def module_path(n):
    return f"plugins.{n}"

name = input("m: ")
importlib.import_module(module_path(name))
