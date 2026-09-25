from passlib.hash import pbkdf2_sha256

password = input("p: ")
hashed = pbkdf2_sha256.hash(password)
