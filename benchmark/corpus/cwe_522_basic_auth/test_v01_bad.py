import requests
from requests.auth import HTTPBasicAuth

pwd = input("p: ")
requests.get("http://api.example.com/data", auth=HTTPBasicAuth("admin", pwd))
