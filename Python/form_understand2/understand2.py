# Exercise form: https://docs.google.com/forms/d/e/1FAIpQLSc5bI2MN24k7JmLUAk1vuFL2JfP18l0SXmSX9Rzz2p20L_LNg/viewform
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/attacks/RSA%20Attacks

# Seems there are 5 modulus, all different, and 5 ciphertexts as long as the modulus. The attacker also knows that the
# public exponent e used for RSA keys generation is 5 for all the keys. Since the attacker knows the low exponent e and 
# at least e = 5 ciphertexts, he can perform an Hamstad Broadcast attack to decrypt the ciphertexts. 

from Crypto.PublicKey import RSA
from data import n1, n2, n3, n4, n5, e, c1, c2, c3, c4, c5


def iroot(k, n):
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


if __name__ == '__main__':
    N = n1*n2*n3*n4*n5

    g, u1, v1 = egcd(N//n1, n1)  
    g, u2, v2 = egcd(N//n2, n2)
    g, u3, v3 = egcd(N//n3, n3) 
    g, u4, v4 = egcd(N//n4, n4)
    g, u5, v5 = egcd(N//n5, n5)

    c = (c1 * u1 * N//n1 + c2 * u2 * N//n2 + c3 * u3 * N//n3 + c4 * u4 * N//n4 + c5 * u5 * N//n5) % (N)

    dec_int = iroot(e, c)
    print(dec_int.to_bytes(dec_int.bit_length()//8 + 1, byteorder='big').decode())