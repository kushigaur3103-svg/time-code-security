from argon2 import PasswordHasher

ph = PasswordHasher()
password = input("p: ")
hashed = ph.hash(password)
