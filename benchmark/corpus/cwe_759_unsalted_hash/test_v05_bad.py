import hashlib

def hash_for_storage(password, legacy):
    if legacy:
        return hashlib.md5(password.encode()).hexdigest()
    return hashlib.sha256(password.encode()).hexdigest()

hash_for_storage(input("p: "), True)
