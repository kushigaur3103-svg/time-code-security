import requests

def fetch_url(url):
    cfg = {"endpoint": url}
    return requests.get(cfg["endpoint"]).text

url = input("url: ")
print(fetch_url(url))
