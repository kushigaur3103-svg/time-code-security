import Crypto.PublicKey.RSA

key = Crypto.PublicKey.RSA.generate(512)
print(key.export_key())
