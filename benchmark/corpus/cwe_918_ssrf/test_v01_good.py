import requests
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def fetch_url(user_url):
    host = urlparse(user_url).netloc
    if host not in ALLOWED:
        raise ValueError("SSRF blocked")
    return requests.get(user_url).text

url = input("url: ")
print(fetch_url(url))
