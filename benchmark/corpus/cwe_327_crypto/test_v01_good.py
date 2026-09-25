import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

pw = input("password: ")
print(hash_password(pw))
