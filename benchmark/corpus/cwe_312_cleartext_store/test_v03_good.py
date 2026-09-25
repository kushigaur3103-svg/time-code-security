password = input("p: ")
vault_client.write("secret/db", password=password)
