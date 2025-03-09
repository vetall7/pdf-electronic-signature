import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import secrets

SALT = secrets.token_bytes(16)


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def transform_pin_to_key_256(pin):
    print("🔐 Transforming pin to key...")
    
    pbkd = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )

    key = pbkd.derive(pin.encode())

    print("🔑 Pin transformed to key successfully")

    return key


def encrypt_private_key(private_key, pin):

    key = transform_pin_to_key_256(pin)

    iv = secrets.token_bytes(16)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    encryptor = cipher.encryptor()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    padding_length = 16 - (len(private_key_bytes) % 16)
    private_key_bytes += bytes([padding_length]) * padding_length

    ct = encryptor.update(private_key_bytes)

    return ct


def main():
    print("🔐 RSA Key Generator")

    while True:
        pin = getpass.getpass("Enter your pin: ")
        confirm_pin = getpass.getpass("Confirm your pin: ")

        if pin != confirm_pin:
            print("❌ Pins do not match")
        else:
            print("✅ Pin set successfully")
            break
    
    print("🔑 Generating RSA keys...")

    
    private_key, public_key = generate_rsa_keys()
    
    print("🔑 RSA keys generated successfully")

    print("🔐 Encrypting private key...")  

    encrypted_private_key = encrypt_private_key(private_key, pin)

    print("🔐 Private key encrypted successfully")


if __name__ == "__main__":
    main()