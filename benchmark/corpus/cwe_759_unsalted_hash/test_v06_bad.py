import hashlib

def store_password(password):
    digest = hashlib.sha256(password.encode()).digest()
    return digest

store_password(input("p: "))
