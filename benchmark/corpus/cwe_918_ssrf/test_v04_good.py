import requests
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

class SafeHttpClient:
    def __init__(self, user_url):
        host = urlparse(user_url).netloc
        if host not in ALLOWED:
            raise ValueError("Blocked")
        self.url = user_url

    def fetch(self):
        return requests.get(self.url).text

url = input("url: ")
print(SafeHttpClient(url).fetch())
