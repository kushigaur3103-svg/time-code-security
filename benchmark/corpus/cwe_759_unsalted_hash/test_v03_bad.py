import hashlib

password = input("p: ")
record = {"username": "bob", "hash": hashlib.md5(password.encode()).hexdigest()}
