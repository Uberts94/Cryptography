import sys
from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes
from params import KEY, NONCE

output = open(sys.argv[2], "wb");

cipher_enc = Salsa20.new(key = KEY, nonce = NONCE)

ciphertext=b''
with open(sys.argv[1], "rb") as finput:
    plaintext = finput.read(1024)
    while plaintext:
        ciphertext += cipher_enc.encrypt(plaintext)
        output.write(ciphertext)
        plaintext = finput.read(1024)

print("File successfully encrypted.\nNONCE: "+str(NONCE))

finput.close()
output.close()