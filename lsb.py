from Crypto.Util.number import *
from gmpy import *

def genKey():
    p = getPrime(512)
    q = getPrime(512)
    n = p*q
    phi = (p-1)*(q-1)
    while True:
        e = getRandomInteger(40)
        if gcd(e,phi) == 1:
            d = int(invert(e,phi))
            return n,e,d
def enc(x,e,n):
    return pow(x,e,n)
def dec(y,d,n):
    return long_to_bytes(pow(y,d,n)).encode("hex")[-2:]
if __name__ == "__main__":
    n,e,d = genKey()
    str = 'hitcon{1east_4ign1f1cant_BYTE_0racle_is_m0re_pow3rfu1!}'
    cipher = enc(bytes_to_long(str),e,n)

    nn = 0
    a = 2
    enc1 = pow(a,e,n)
    while gcd(nn, 614889782588491410) > 1:
        enc2 = pow(a**2,e,n)
        nn = gcd(nn, (enc2 - enc1**2))
        enc1, a = enc2, a **2
    cipher = int(cipher)
    nn = int(nn)
    LB = 0
    UB = nn
    for i in xrange(1024):
        print 'round ', i
        pt = pow(2,i+1,nn)
        new_cipher = enc(pt,e,n)*cipher % nn
        possible = (LB+UB)/2
        if int(dec(new_cipher,d,n),16) %2 == 0:
            UB = possible
        else:
            LB = possible
        if LB >= UB:
            break

    print '\nFlag\n'
    print hex(LB).strip('L')[2:].decode('hex')
    print hex(UB).strip('L')[2:].decode('hex')










