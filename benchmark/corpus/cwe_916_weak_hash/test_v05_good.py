import hashlib

data = input("f: ")
digest = hashlib.sha256(data.encode()).hexdigest()
