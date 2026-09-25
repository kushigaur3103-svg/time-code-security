import requests
from requests.auth import HTTPBasicAuth

pwd = input("p: ")
requests.get("https://api.example.com/data", auth=HTTPBasicAuth("admin", pwd))
