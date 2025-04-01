"""
@file: main.py
@brief: This script generates RSA keys and encrypts the private key using a PIN.
@details: The script uses the cryptography library to generate RSA keys and encrypt the private key.
"""
import getpass
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    """
    @brief: This function generates RSA keys.
    @details: It generates a private key and derives the public key from it.
    @return: The generated private and public keys.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    public_key = private_key.public_key()

    return private_key, public_key


def transform_pin_to_key_256(pin):
    """
    @brief: This function transforms a PIN into a 256-bit key using SHA-256 hashing.
    @details: It encodes the PIN and hashes it to create a key.
    @param pin: The PIN to be transformed into a key.
    @return: The generated key.
    """
    print("🔐 Transforming pin to key...")
    
    hash = hashlib.sha256(pin.encode()).digest()

    print("🔑 Pin transformed to key successfully")

    return hash


def encrypt_private_key(private_key, pin):
    """
    @brief: This function encrypts the private key using a PIN.
    @details: It uses the PIN to derive a key and encrypts the private key.
    @param private_key: The private key to be encrypted.
    @param pin: The PIN used to encrypt the private key.
    @return: The encrypted private key.
    """
    key = transform_pin_to_key_256(pin)

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key) # AES-256
    )

    return private_key_bytes


def save_private_key(encrypted_private_key):
    """"
    @brief: This function saves the encrypted private key to a file.
    @details: It writes the encrypted private key to a file named 'private_key.pem'.
    @param encrypted_private_key: The encrypted private key to be saved.
    """
    with open("private_key.pem", "wb") as f:
        f.write(encrypted_private_key)
        print("🔑 Private key saved successfully to private_key.pem")


def save_public_key(public_key):
    """"
    @brief: This function saves the public key to a file.
    @details: It writes the public key to a file named 'public_key.pem'.
    @param public_key: The public key to be saved.
    """
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("🔑 Public key saved successfully to public_key.pem")


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

    print("💾 Saving keys to files...")

    save_private_key(encrypted_private_key)

    save_public_key(public_key)


if __name__ == "__main__":
    main()