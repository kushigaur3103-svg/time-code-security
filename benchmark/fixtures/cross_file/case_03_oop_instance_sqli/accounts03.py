from gateway03 import run_lookup


class UserService:
    def search(self, account_token):
        return run_lookup(account_token)
