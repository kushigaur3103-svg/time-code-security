import requests

def build_request(url):
    return requests.get(url)

def fetch_url(url):
    return build_request(url).text

url = input("url: ")
print(fetch_url(url))
