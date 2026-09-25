import hashlib

def store_password(password, legacy):
    if legacy:
        return hashlib.sha1(password.encode()).hexdigest()
    return hashlib.sha256(password.encode()).hexdigest()

store_password(input("p: "), False)
