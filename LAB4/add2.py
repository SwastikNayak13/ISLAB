import math
from sympy import isprime

# Function to generate small RSA key pair
def generate_vulnerable_rsa_keypair():
    # Use small prime numbers (vulnerable to attack)
    p = 61  # Small prime
    q = 53  # Small prime
    n = p * q  # RSA modulus
    phi_n = (p - 1) * (q - 1)  # Euler's totient
    e = 17  # Public exponent, must be coprime to phi_n
    d = pow(e, -1, phi_n)  # Private exponent (modular multiplicative inverse)
    return (n, e), (n, d)

# Function to perform the attack
def attack_rsa(n, e):
    # Factor n to find p and q
    # This works because n is small and we can enumerate possible factors
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            p = i
            q = n // i
            if isprime(q):
                # Successfully factored n into p and q
                phi_n = (p - 1) * (q - 1)
                d = pow(e, -1, phi_n)  # Compute private exponent
                return p, q, d
    return None

def main():
    # Generate vulnerable RSA keys
    public_key, private_key = generate_vulnerable_rsa_keypair()
    n, e = public_key
    print(f"Public Key: (n={n}, e={e})")
    print(f"Private Key: (n={private_key[0]}, d={private_key[1]})")

    # Attempt to attack the RSA key pair
    p, q, d = attack_rsa(n, e)
    if d:
        print(f"Attack Successful! Found p: {p}, q: {q}, d: {d}")
    else:
        print("Attack Failed: Unable to factor n.")

if __name__ == "__main__":
    main()
"""Key Generation:

    The generate_vulnerable_rsa_keypair function creates an RSA key pair using small prime numbers pp and qq. The modulus nn is computed as n=p×qn=p×q, and the public exponent ee is chosen to be 17. The private exponent dd is calculated using the modular inverse.

Attack Function:

    The attack_rsa function attempts to factor the modulus nn to retrieve the prime factors pp and qq. It iterates through possible divisors up to nn

    ​. Once it finds pp, it calculates qq and verifies if qq is prime. If successful, it computes the private exponent dd.

Main Execution:

    The main function generates the vulnerable RSA keys and then attempts to attack the key pair to recover the private key."""