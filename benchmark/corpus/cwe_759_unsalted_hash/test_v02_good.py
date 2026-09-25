import bcrypt

password = input("p: ")
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
