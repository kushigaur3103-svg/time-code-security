import hashlib

class Account:
    def __init__(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

account = Account(input("p: "))
