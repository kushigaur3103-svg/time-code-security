import hashlib

token = input("t: ")
with open("tokens.txt", "w") as f:
    f.write(hashlib.sha256(token.encode()).hexdigest())
