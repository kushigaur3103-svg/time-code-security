import requests

data = {"token": "abc123"}
if primary:
    requests.post("http://primary.example.com/api", json=data)
else:
    requests.post("http://backup.example.com/api", json=data)
