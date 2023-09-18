# Form exercise: https://docs.google.com/forms/d/e/1FAIpQLSdF3bUEzytiG3HRz1PQWtCzbFx3F5XH1OFirmx9MfVQFD4H2Q/viewform
# Followed: https://github.com/aldobas/cryptography-03lpyov-exercises/tree/master/AY2223/Python/attacks/RSA%20Attacks

# In this case, the attacker doesn't have a lot of information. Seems there are an exponent, the forth number of the Fermat sequence,
# an a modulus n. In this case, the attacker can try to use factorDB or Yafu. Another possible solution is to use the Fermat 
# Fermat Factorization

from data import modulus
from factordb.factordb import FactorDB
from gmpy2 import isqrt

def fermat(n):
        print("init")

        a = isqrt(n)
        b = a
        b2 = pow(a,2) - n

        print("a= "+str(a))
        print("b= " + str(b))

        print("b2=" + str(b2))
        print("delta-->" + str(pow(b, 2) - b2 % n)+"\n-----------")
        print("iterate")
        i = 0

        while True:
            if b2 == pow(b,2):
                print("found at iteration "+str(i))
                break;
            else:
                a +=1
                b2 = pow(a, 2) - n
                b = isqrt(b2)
            i+=1
            print("iteration="+str(i))
            print("a= " + str(a))
            print("b= " + str(b))
        print("b2 =" + str(b2))
        print("delta-->" + str(pow(b, 2) - b2 % n) + "\n-----------")

        p = a+b
        q = a-b

        return p,q

if __name__ == '__main__':
    f = FactorDB(modulus)
    f.connect()
    response = f.get_factor_list()

    if response[0] != modulus:
        print("Ok, factors found. It's possible to reconstruct the RSA private key")
    else :
        print("Modulus not matched in factorDB. Let's try with Fermat Factorization....")

        p,q = fermat(modulus)

        print("Factors found:")
        print("p = "+str(p))
        print("q = " + str(q))