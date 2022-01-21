# from Crypto.PublicKey import RSA 
# from cryptography.fernet import Fernet

#Public key generation
# key = RSA.generate(2048)
# public_key = key.publickey().export_key()
# publick_file  = open("pub.pem", "wb")
# publick_file.write(public_key)
# publick_file.close()

#Private key generation
# private_key = key.export_key()
# privatek_file = open("priv.pem", "wb")
# privatek_file.write(private_key)
# privatek_file.close()

# _key = Fernet.generate_key()
# with open("key.key", 'wb') as _file_k:
#     _file_k.write(_key)