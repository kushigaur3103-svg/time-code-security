import importlib

name = input("m: ")
cfg = {"module": name}
importlib.import_module(cfg["module"])
