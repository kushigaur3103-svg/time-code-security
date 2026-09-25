from urllib.parse import urlparse

class AuthHandler:
    def __init__(self, next_url):
        parsed = urlparse(next_url)
        self.redirect_url = next_url if not (parsed.scheme or parsed.netloc) else "/"

    def finish_login(self):
        print(f"Location: {self.redirect_url}")

next_url = input("next: ")
AuthHandler(next_url).finish_login()
