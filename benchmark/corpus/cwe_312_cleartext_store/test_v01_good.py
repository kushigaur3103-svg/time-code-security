from cryptography.fernet import Fernet

password = input("p: ")
encrypted = fernet.encrypt(password.encode())
with open("creds.bin", "wb") as f:
    f.write(encrypted)
