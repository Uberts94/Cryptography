from sys import argv
import base64
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
from params import KEY, NONCE

cipher_dec = Salsa20.new(key=KEY, nonce=NONCE)

decrypted=b''
with open(argv[1], "rb") as fencrypted:
    ciphertext = fencrypted.read(1024)
    while ciphertext:
        decrypted += cipher_dec.decrypt(ciphertext)
        print(decrypted)
        ciphertext = fencrypted.read(1024)
    
fencrypted.close()