from pwn import *
from gmpy import *
 
p = remote('127.0.0.1',4445)
p.recvuntil('flag!\n')
enc = p.recvuntil('\n',drop=True).strip()
enc = '0x'+enc
# ciphertext of flag
ENC = int(enc,16)

def s2n(s):
    """
    String to number.
    """
    if not len(s):
       return 0
    return int(s.encode("hex"), 16)

def n2s(n):
    """
    Number to string.
    """
    s = hex(n)[2:].rstrip("L")
    if len(s) % 2 != 0:
        s = "0" + s
    return s.decode("hex")
# send plaintext for server
# server would calculate the cipher
# return to you
def oracle_enc(x):
    p.recvuntil('cmd:')
    p.sendline('A')
    p.recvuntil('input:')
    p.sendline(n2s(x).encode("hex"))
    ret = p.recvuntil('\n',drop=True).strip()
    ret = int(ret,16)
    return ret
# send cipher to server
# server would only send the last byte back
def oracle_dec(y):
    p.recvuntil('cmd:')
    p.sendline('B')
    p.recvuntil('input:')
    p.sendline(n2s(y).encode('hex'))
    ret = p.recvuntil('\n',drop=True).strip()
    ret = int(ret, 16) 
    return ret

# use Extended Euclidean Algorithm
def egcd(a , b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b%a,a)
    return (g, x - (b//a) * y, y)
# find modular multiplicative inverse 
# using Extended Euclidean Algorithm
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x%m

a = 2
# it enc of a, not parameter 'e' of rsa 
e = oracle_enc(a)
n = 0
# find the n 
# enc = enc(a) = a^e mod n
# enc2 = enc(a^2) = a^2e mod n
# a^e = enc + n*k1
# a^2e = enc2 + n*k2
# (a^e)^2 = (enc+n*k1)^2
# enc2 - enc*enc = n * ( X ) it no matter what X is
# we know that (enc2 - enc * enc ) is n's multiple
# we can find n with gcd( n , enc2 - enc * enc) in iterative
# until gcd(n, factorial of prime) > 1
# such that n is not prime, because it is product of two prime number
# finally, we find the n to attack the rsa
while gcd(n, 614889782588491410) > 1:
    ee = oracle_enc(a**2)
    n = gcd(n , ee - e**2)
    e, a = ee, a**2


# in this section
# using "least significant byte" oracle attack
# to crack the each byte of ciphertext
# we already know the plaintext is 68 characters
# so it must be compute 128 at most


sflag = ""
vflag = 0

for i in range(128):
    # we construct a mulitpliar inverse of 256^i mod n
    # thus, we can encrypt inv to get inv^e mod n
    # and then calculate the ((inv^e * flag^e) mod n) ^ d
    potinv = modinv(256**i,n)
    enck = oracle_enc(potinv)
    msg = oracle_dec(enck * ENC)
    # now we get flag*inv mod 256
    # we also know that flag = knownsofar + 256*restofflag
    # flag * inv mod n = restofflag + knownsofar*inv
    # vflag is previous round msg
    # sflag is recently decrypted flag
    msg = (msg - (potinv * vflag) % n) % 256
    print chr(msg),'\b',
    vflag += msg * 2 **(8*i)
    sflag = chr(msg) + sflag
    if 'hitcon' in sflag:
        break

print '\n\nflag :',sflag


