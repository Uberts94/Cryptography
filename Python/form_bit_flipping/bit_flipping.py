# Exercise form: https://docs.google.com/forms/d/e/1FAIpQLSed2C2wXQfcfXihUa4-l2vQmDOhfTCPzPcPMV14uIb-HEVwMg/viewform
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/blob/master/AY2223/Python/attacks/BF/bitflippling_video.py
from params import KEY, NONCE
from Crypto.Cipher import Salsa20

###########################################################################################

# Attacker knows the file starts with the current date in the format dd/mm/yyyy: 16/09/2023.
# So, if he knows the encrypted data, by means of the bit flipping attack can force a new 
# value for the data.

# Reading the encrypted file
input = b''
with open("ciphertext.enc", "rb") as fin:
    read = fin.read(1024)
    while read:
        input += read
        read = fin.read(1024)

#The whole data string is 10 bytes long
ciphertext = bytearray(input);

new_tens = b'1'
new_tens_ascii = ord(new_tens)

#Mask for the first char of the month
mask1 = ord('0')^new_tens_ascii

edt_ciphertext = bytearray(ciphertext)
edt_ciphertext[3] = ciphertext[3]^mask1

new_units = b'0'
new_units_ascii = ord(new_units)

#Mask for the second char of the month
mask2 = ord('9')^new_units_ascii

edt_ciphertext[4] = ciphertext[4]^mask2

fin.close()

# Writing the edited ciphertext in the encrypted file

with open("ciphertext.enc", "wb") as fout:
    fout.write(edt_ciphertext)

fout.close()

###########################################################################################

# Attacker sends to the victim the modified ciphertext. The victim decrypts the ciphertext

cipher = Salsa20.new(KEY, NONCE)
fout = open("victim.dec", "wb")

with open("ciphertext.enc", "rb") as fin:
    ciphertext = fin.read(1024)
    while ciphertext:
        decrypted = cipher.decrypt(ciphertext)
        fout.write(decrypted)
        ciphertext = fin.read(1024)

print("File successfully decrypted.\n")