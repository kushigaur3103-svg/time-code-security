from flask import redirect

class AuthHandler:
    def __init__(self, next_url):
        self.redirect_url = next_url

    def finish_login(self):
        return redirect(self.redirect_url)

next_url = input("next: ")
print(AuthHandler(next_url).finish_login())
