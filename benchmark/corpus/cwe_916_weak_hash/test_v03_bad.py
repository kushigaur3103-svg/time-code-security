import hashlib

password = input("p: ")
record = {"username": "alice", "hash": hashlib.sha256(password.encode()).hexdigest()}
