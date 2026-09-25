import requests
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def fetch_url(user_url, use_cache):
    host = urlparse(user_url).netloc
    if host not in ALLOWED:
        raise ValueError("Blocked")
    if use_cache:
        return "cached-response"
    return requests.get(user_url).text

url = input("url: ")
print(fetch_url(url, False))
