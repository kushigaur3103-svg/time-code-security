import requests
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def validate_url(user_url):
    host = urlparse(user_url).netloc
    if host not in ALLOWED:
        raise ValueError("Blocked")
    return user_url

def fetch_url(user_url):
    safe = validate_url(user_url)
    return requests.get(safe).text

url = input("url: ")
print(fetch_url(url))
