access_token = input("t: ")
with open("tokens.txt", "a") as f:
    f.write(access_token)
