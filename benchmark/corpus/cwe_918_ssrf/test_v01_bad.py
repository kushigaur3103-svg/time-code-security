import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text

url = input("url: ")
print(fetch_url(url))
