from Crypto.PublicKey import RSA

key = RSA.generate(bits=2048)
print(key.export_key())
