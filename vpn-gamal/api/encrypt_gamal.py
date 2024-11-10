import random
from sympy import nextprime, mod_inverse
import MySQLdb

class ElGamal:
    def __init__(self):
        self.p = None  # Large prime
        self.g = None  # Generator
        self.x = None  # Private key
        self.h = None  # Public component h = g^x mod p

    def generate_keys(self):
        """Generate the ElGamal public and private keys."""
        self.p = self._generate_large_prime()
        self.g = random.randint(2, self.p - 1)
        self.x = random.randint(1, self.p - 2)
        self.h = pow(self.g, self.x, self.p)
        self._store_keys_in_db()

    def _generate_large_prime(self):
        """Generate a large prime number."""
        prime_candidate = random.randint(10**5, 10**6)
        return nextprime(prime_candidate)

    def _store_keys_in_db(self):
        """Store the generated keys in the MySQL database."""
        db = MySQLdb.connect(host="mysql-vpn", user="root", passwd="root", db="secret_msg")
        cursor = db.cursor()
        
        query = """
            INSERT INTO elgamal_keys (prime, generator, h, private_key) 
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (self.p, self.g, self.h, self.x))
        
        db.commit()
        cursor.close()
        db.close()

    def encrypt(self, plaintext):
        """Encrypt a plaintext message using the public key (p, g, h)."""
        ciphertext = []
        for char in plaintext:
            y = random.randint(1, self.p - 2)  # Random ephemeral key
            c1 = pow(self.g, y, self.p)
            c2 = (ord(char) * pow(self.h, y, self.p)) % self.p
            ciphertext.append((c1, c2))
        return ciphertext

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext using the private key x."""
        decrypted_text = ''
        for c1, c2 in ciphertext:
            s = pow(c1, self.x, self.p)
            s_inv = mod_inverse(s, self.p)
            decrypted_char = chr((c2 * s_inv) % self.p)
            decrypted_text += decrypted_char
        return decrypted_text

    def get_public_key(self):
        """Return the public key (p, g, h)."""
        return (self.p, self.g, self.h)

    def get_private_key(self):
        """Return the private key x."""
        return self.x


# Global instance to maintain ElGamal state
elgamal_instance = None

def connect():
    """Establish a connection and generate new ElGamal keys."""
    global elgamal_instance
    elgamal_instance = ElGamal()
    elgamal_instance.generate_keys()
    print("ElGamal keys generated and stored in MySQL.")

def disconnect():
    """Disconnect and reset the ElGamal instance."""
    global elgamal_instance
    elgamal_instance = None

def elgamal_encrypt(plaintext):
    """Encrypt the plaintext using the global ElGamal instance."""
    if elgamal_instance is None:
        raise ValueError("ElGamal instance not connected.")
    return elgamal_instance.encrypt(plaintext)

def elgamal_decrypt(ciphertext):
    """Decrypt the ciphertext using the global ElGamal instance."""
    if elgamal_instance is None:
        raise ValueError("ElGamal instance not connected.")
    return elgamal_instance.decrypt(ciphertext)

def elgamal_get_keys():
    """Return the public and private keys."""
    if elgamal_instance is None:
        raise ValueError("ElGamal instance not connected.")
    public_key = elgamal_instance.get_public_key()
    private_key = elgamal_instance.get_private_key()
    return public_key, private_key 
