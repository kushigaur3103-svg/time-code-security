import hashlib

def store_password(password):
    hashes = {"password_hash": hashlib.md5(password.encode()).hexdigest()}
    print(f"Stored: {hashes['password_hash']}")

pw = input("password: ")
store_password(pw)
