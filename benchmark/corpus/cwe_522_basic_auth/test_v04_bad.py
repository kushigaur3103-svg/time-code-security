import requests
import base64

token = base64.b64encode(b"admin:secret").decode()
headers = {"Authorization": f"Basic {token}"}
requests.get("http://api.example.com/v1", headers=headers)
