# Exercise form: https://docs.google.com/forms/d/e/1FAIpQLSdymZ9cAjUsvvPzhYLl93bOF0I7mS_Bhj-HcD2GrB23jgKkwQ/viewform
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/attacks/RSA%20Attacks

# For each x, the first value probably represent the modulus.
# The second one, the same for every x, is 3 and represent the public exponent e
# The third one is probably the ciphertext. 
# The lenght of the ciphertext is less than the lenght of the own modulus. For
# this reason, the fastest attack we can perform is a low public exponent attack.
# It's the fastest in this case because, since the ciphertext len is under the threshold
# represented by the modulus, it's not reduced by the modulus operation and we can easly
# decrypt the message using the iroot function

from data import x1, x2, x3, x4, x5, c1, c2, c3, c4, c5
from Crypto.PublicKey import RSA

#kth root of the number n
def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

if __name__ == '__main__':

    print("X1 stats")
    print("X1 modulus lenght: "+str(len(x1[0])))
    print("X1 ciphertext lenght: "+str(len(x1[2])))
    print("----------------------------------------\nX2 stats")
    print("X2 modulus lenght: "+str(len(x2[0])))
    print("X2 ciphertext lenght: "+str(len(x2[2])))
    print("----------------------------------------\nX3 stats")
    print("X3 modulus lenght: "+str(len(x3[0])))
    print("X3 ciphertext lenght: "+str(len(x3[2])))
    print("----------------------------------------\nX4 stats")
    print("X4 modulus lenght: "+str(len(x4[0])))
    print("X4 ciphertext lenght: "+str(len(x4[2])))
    print("----------------------------------------\nX5 stats")
    print("X5 modulus lenght: "+str(len(x5[0])))
    print("X5 ciphertext lenght: "+str(len(x5[2])))

    print("----------------------------------------\nDecripting the ciphertexts for all x (NOTE that all the x contains the same value for the ciphertext)\n")

    e = 3

    decrypted = iroot(e, c1)
    print("Decrypting x1: "+decrypted.to_bytes(decrypted.bit_length() // 8 +1, byteorder='big').decode())
    decrypted = iroot(e, c2)
    print("Decrypting x2: "+decrypted.to_bytes(decrypted.bit_length() // 8 +1, byteorder='big').decode())
    decrypted = iroot(e, c3)
    print("Decrypting x3: "+decrypted.to_bytes(decrypted.bit_length() // 8 +1, byteorder='big').decode())
    decrypted = iroot(e, c4)
    print("Decrypting x4: "+decrypted.to_bytes(decrypted.bit_length() // 8 +1, byteorder='big').decode())
    decrypted = iroot(e, c5)
    print("Decrypting x5: "+decrypted.to_bytes(decrypted.bit_length() // 8 +1, byteorder='big').decode())

    print("----------------------------------------\n")
    print("Since the ciphertext is too small for the modulus n, every ciphertext, which len is less than the modulus len, \ncan be easly descripted (even if we don't know the key.)");

    print("\n\nGenerating new RSA 1024 key....")
    rsa_keypair = RSA.generate(1024, e = 3)
    print(rsa_keypair.public_key)

    e = rsa_keypair.e
    n = rsa_keypair.n

    print("\n\nCiphering the previous descripted messages:")
    msg = decrypted
    c = pow(msg, e, n)
    print(c)

    decrypted_msg = iroot(3, c)
    print("Decrypting... \n"+decrypted_msg.to_bytes(decrypted_msg.bit_length() // 8+1, byteorder='big').decode())
    print("As espected, the program returns exactly the same message decrypted from the input ciphertext, even if")
    print("it has been encrypted with a randomly generated new RSA key.\n")