import requests

password = input("p: ")
requests.post("https://api.example.com/login", json={"user": "alice", "password": password})
