password = input("p: ")
with open("creds.txt", "w") as f:
    f.write(password)
