import requests
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

def fetch_url(user_url):
    cfg = {"url": user_url, "host": urlparse(user_url).netloc}
    if cfg["host"] not in ALLOWED:
        raise ValueError("Blocked")
    return requests.get(cfg["url"]).text

url = input("url: ")
print(fetch_url(url))
