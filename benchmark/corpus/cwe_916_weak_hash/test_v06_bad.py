import hashlib

password = input("p: ")
salt = "static-salt"
digest = hashlib.sha256((password + salt).encode()).hexdigest()
