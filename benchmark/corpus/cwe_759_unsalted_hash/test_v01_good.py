import hashlib
import os

password = input("p: ")
salt = os.urandom(16)
digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000)
