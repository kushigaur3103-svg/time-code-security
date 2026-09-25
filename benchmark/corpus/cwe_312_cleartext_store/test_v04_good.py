api_key = input("k: ")
with open("tokens.txt", "w") as f:
    f.write(mask_secret(api_key))
