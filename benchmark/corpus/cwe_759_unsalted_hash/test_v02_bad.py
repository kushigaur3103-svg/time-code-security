import hashlib

passwd = input("p: ")
digest = hashlib.sha1(passwd.encode()).hexdigest()
