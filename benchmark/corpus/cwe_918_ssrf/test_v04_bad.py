import requests

class HttpClient:
    def __init__(self, url):
        self.url = url

    def fetch(self):
        return requests.get(self.url).text

url = input("url: ")
print(HttpClient(url).fetch())
