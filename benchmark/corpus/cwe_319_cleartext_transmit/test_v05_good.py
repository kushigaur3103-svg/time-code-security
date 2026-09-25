import requests

data = {"token": "abc123"}
if primary:
    requests.post("https://primary.example.com/api", json=data)
else:
    requests.post("https://backup.example.com/api", json=data)
