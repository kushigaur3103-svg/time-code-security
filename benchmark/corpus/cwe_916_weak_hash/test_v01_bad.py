import hashlib

password = input("p: ")
digest = hashlib.sha256(password.encode()).hexdigest()
