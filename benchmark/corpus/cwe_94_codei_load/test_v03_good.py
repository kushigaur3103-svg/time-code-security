name = input("m: ")
if name in {"auth", "reports"}:
    __import__(name)
