from Crypto.PublicKey import RSA

key = RSA.generate(2 * 512)
print(key.export_key())
