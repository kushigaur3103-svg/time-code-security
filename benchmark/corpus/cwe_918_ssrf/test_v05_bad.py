import requests

def fetch_url(url, use_cache):
    if use_cache:
        return requests.get(url).text
    else:
        return requests.get(url).text

url = input("url: ")
print(fetch_url(url, False))
