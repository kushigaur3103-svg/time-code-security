import hashlib

def hash_password(password, legacy):
    if legacy:
        return hashlib.md5(password.encode()).hexdigest()
    else:
        return hashlib.sha1(password.encode()).hexdigest()

pw = input("password: ")
print(hash_password(pw, True))
