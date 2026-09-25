import requests

class ApiClient:
    def __init__(self, url):
        self.url = url
        self.verify_ssl = False

    def get_insecure(self):
        # OOP flow: instance attribute sets verify
        return requests.get(self.url, verify=self.verify_ssl)

client = ApiClient("https://api.internal.example.com/data")
resp = client.get_insecure()
print(resp.status_code)
