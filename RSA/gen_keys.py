import math
import random
import fractions

rand = random.SystemRandom() # Uses os.urandom

def miller_rabin_primality(n, k = 256):
    """Use the Miller-Rabin primality test to determine if the number is likely prime"""
    if n & 1 == 0: # Divisible by 2
        return False
    else:
        r = 0
        d = n - 1
        while d & 1 == 0:
            r += 1
            d >>= 1
        for _ in range(k):
            a = rand.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == 1:
                    return False
                if x == n - 1:
                    break
            else:
                return False
        return True

def lcm(a, b):
    return a * b // fractions.gcd(a, b)

# Modular multiplicative inverse from wikibooks:
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def gen_random_prime(bit_length):
    """Generate a random k prime number that is greater than sqrt(2)*2^(k-1)"""
    minimum = 6074001000 << (bit_length - 33) # sqrt(2) * 2^(k - 1)
    maximum = (1 << bit_length) - 1 # 2^k - 1
    while 1:
        p = rand.randint(minimum, maximum)
        if miller_rabin_primality(p):
            return p

def gen_keys(key_size=2048):
    e = 65537

    while 1:
        p = gen_random_prime(key_size // 2)
        q = gen_random_prime(key_size // 2)
        lam = lcm(p - 1, q - 1)
        if fractions.gcd(e, lam) == 1 and (abs(p - q) >> (key_size // 2 - 100)) != 0:
            break

    n = p * q # public key
    d = modinv(e, lam) # private key
    return n, d