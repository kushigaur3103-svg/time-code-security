from Crypto.PublicKey import RSA

key = RSA.generate(bits=1024)
print(key.export_key())
