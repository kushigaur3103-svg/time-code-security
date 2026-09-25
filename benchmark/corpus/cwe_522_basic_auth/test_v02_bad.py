import requests

password = input("p: ")
requests.post("http://service.corp/login", auth=("admin", password))
