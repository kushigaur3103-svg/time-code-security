import requests

password = input("p: ")
requests.post("http://api.example.com/login", json={"user": "alice", "password": password})
