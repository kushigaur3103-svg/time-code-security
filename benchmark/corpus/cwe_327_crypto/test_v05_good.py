import hashlib

def hash_password(password, legacy):
    if legacy:
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        return hashlib.sha256(password.encode()).hexdigest()

pw = input("password: ")
print(hash_password(pw, True))
