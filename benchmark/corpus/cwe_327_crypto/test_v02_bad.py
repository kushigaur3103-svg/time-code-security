import hashlib

def compute_digest(data):
    return hashlib.md5(data.encode()).hexdigest()

def store_password(password):
    digest = compute_digest(password)
    print(f"Stored: {digest}")

pw = input("password: ")
store_password(pw)
