from user_repo import find_user_by_name

class AccountService:
    def fetch_account(self, account_name):
        # Method call forwarding to repo sink
        return find_user_by_name(raw_name=account_name)