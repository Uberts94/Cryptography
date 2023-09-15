#Form exercise: https://docs.google.com/forms/d/e/1FAIpQLSfSSE5U087uMkvvn4_IetHmteAklsDzX8wUDGFs51xt2urBrw/viewform
#Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/attacks/ECB/ECB_ACPA

# An encryption oracle, listening on IP:port, receives as input a string and
# returns another string that encodes in hexadecimal the result of the
# encryption with AES in ECB mode of the following plaintext
# message = """Here is the msg to cipher{0}{1}""".format( input, secret)
# where input is the string received as input and secret is
# a secret string, composed of 16 printable characters
# Complete the program so that the secret is discovered without brute forcing
# the whole search space

import os
os.environ['PWNLIB_NOTERM'] = 'True'  # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from Crypto.Cipher import AES
from pwn import *
import string

from myconfig import HOST,PORT

SECRET_LEN = 16

prefix = "A" * (AES.block_size - len("to cipher"))
secret = ""
for j in range(1, SECRET_LEN+1):
    pad1 = "A" * (AES.block_size - j)
    pad2 = "A" * (AES.block_size - j)
    for i in string.printable :
        server = remote(HOST, PORT)

        msg = prefix+pad1+secret+i+pad2
        print("Sending msg "+msg)
        server.send(msg)
        ciphertext = server.recv(1024)
        server.close()

        if ciphertext[32:48] == ciphertext[48:64] :
            print("Found new character = "+i)
            secret+=i
            pad1 = pad1[1:]
            pad2 = pad2[1:]
            break

print("Secret discovered = "+secret)