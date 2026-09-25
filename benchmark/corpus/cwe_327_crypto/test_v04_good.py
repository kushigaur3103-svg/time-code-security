import hashlib

class PasswordStore:
    def __init__(self, password):
        self.digest = hashlib.sha256(password.encode()).hexdigest()

    def save(self):
        print(f"Stored: {self.digest}")

pw = input("password: ")
PasswordStore(pw).save()
