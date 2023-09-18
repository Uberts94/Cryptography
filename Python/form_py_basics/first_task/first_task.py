# Exercise form: https://docs.google.com/forms/d/e/1FAIpQLSckv7IYOXzDv_uQfdrV0wRA4K9gGm1cwpEeKQBCmzCOnY8qVQ/viewform
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/basics

# Write a piece of code that encrypts with AES the content of a file whose name 
# is taken from mydata (filein) and save the output whose name is taken from mydata (fileout).

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from mykeys import aes_key
from mydata_ex import  filein, fileout

IV = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC, IV)

f_input = open(filein, "rb")
input_data = f_input.read(1024)
ciphertext = cipher.encrypt(pad(input_data,AES.block_size))

f_output = open(fileout, "wb")
f_output.write(ciphertext)

f_input.close()
f_output.close()

#########################################################################
# Testing Decryption....

# encrypted = open(fileout, "rb")

# cipher_dec = AES.new(aes_key, AES.MODE_CBC, IV)
# message_enc = encrypted.read(1024)
# plaintext = cipher_dec.decrypt(message_enc)
# unpadded = unpad(plaintext, AES.block_size)


# print("Decrypted message: "+str(unpadded))