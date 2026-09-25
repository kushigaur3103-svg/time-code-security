import requests

password = input("p: ")
requests.post("https://service.corp/login", auth=("admin", password))
