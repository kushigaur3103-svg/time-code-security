import os
import requests

scheme = os.environ.get("API_SCHEME")
if scheme != "https":
    raise ValueError("insecure scheme")
requests.get(f"{scheme}://api.example.com/data")
