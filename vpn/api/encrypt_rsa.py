import random
from sympy import nextprime

class RSA:
    def __init__(self):
        self.p = None  
        self.q = None  
        self.n = None  # Modulus (n = p * q)
        self.e = 65537  
        self.d = None  

    def generate_primes(self):
        """Generate two large prime numbers and calculate keys."""
        self.p = self._generate_prime()
        self.q = self._generate_prime()
        self.n = self.p * self.q
        self._calculate_private_key()

    def _generate_prime(self):
        """Generate a large random prime number."""
        prime_candidate = random.randint(10**5, 10**6)
        return nextprime(prime_candidate)

    def _calculate_private_key(self):
        """Calculate the private key (d) using Euler's totient."""
        phi = (self.p - 1) * (self.q - 1)
        self.d = self._modinv(self.e, phi)

    def _egcd(self, a, b):
        """Extended GCD algorithm."""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self._egcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def _modinv(self, a, m):
        """Calculate modular inverse using the extended GCD algorithm."""
        gcd, x, _ = self._egcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    def encrypt(self, plaintext):
        """Encrypt a plaintext message using the public key."""
        return [pow(ord(char), self.e, self.n) for char in plaintext]

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext using the private key."""
        return ''.join([chr(pow(char, self.d, self.n)) for char in ciphertext])

    def get_public_key(self):
        """Return the public key (n, e)."""
        return (self.n, self.e)

    def get_private_key(self):
        """Return the private key (n, d)."""
        return (self.n, self.d)


# Global instance to maintain RSA state
rsa_instance = None

def connect():
    """Establish a connection and generate new RSA keys."""
    global rsa_instance
    rsa_instance = RSA()
    rsa_instance.generate_primes()
    print("RSA keys generated.")

def disconnect():
    """Disconnect and reset the RSA instance."""
    global rsa_instance
    rsa_instance = None

def rsa_encrypt(plaintext):
    """Encrypt the plaintext using the global RSA instance."""
    if rsa_instance is None:
        raise ValueError("RSA instance not connected.")
    return rsa_instance.encrypt(plaintext)

def rsa_get_keys():
    """Return the public and private keys."""
    if rsa_instance is None:
        raise ValueError("RSA instance not connected.")
    public_key = rsa_instance.get_public_key()
    private_key = rsa_instance.get_private_key()
    return public_key, private_key
