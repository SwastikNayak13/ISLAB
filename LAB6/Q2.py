import random
from sympy import isprime


def generate_large_prime(bits=256):
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))


def dh_keygen(bits=256):
    p, g = generate_large_prime(bits), random.randint(
        2, (p := generate_large_prime(bits)) - 2
    )
    a, b = random.randint(1, p - 2), random.randint(1, p - 2)
    A, B = pow(g, a, p), pow(g, b, p)
    return (p, g, A, B), (pow(B, a, p), pow(A, b, p))


(pub, (sec_A, sec_B)) = dh_keygen()
print("Public values (p, g, A, B):", *pub)
print("Shared secrets match?", sec_A == sec_B)