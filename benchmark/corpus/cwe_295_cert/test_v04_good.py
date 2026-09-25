import requests

class ApiClient:
    def __init__(self):
        self.verify_ssl = True

    def get(self, url):
        return requests.get(url, verify=self.verify_ssl)

client = ApiClient()
resp = client.get("https://api.internal.example.com/data")
print(resp.status_code)
