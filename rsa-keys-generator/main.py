import getpass
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    public_key = private_key.public_key()

    return private_key, public_key


def transform_pin_to_key_256(pin):
    print("🔐 Transforming pin to key...")
    
    hash = hashlib.sha256(pin.encode()).digest()

    print("🔑 Pin transformed to key successfully")

    return hash


def encrypt_private_key(private_key, pin):

    key = transform_pin_to_key_256(pin)

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key) # AES-256-CBC
    )

    return private_key_bytes


def save_private_key(encrypted_private_key):
    with open("private_key.pem", "wb") as f:
        f.write(encrypted_private_key)
        print("🔑 Private key saved successfully to private_key.pem")

    # media_dir = '/media'
    # user = os.getlogin()
    # media_dir = f'/media/{user}'
    # if os.path.exists(media_dir):
    #     usb_drives = [os.path.join(media_dir, d) for d in os.listdir(media_dir)
    #                     if os.path.isdir(os.path.join(media_dir, d))]
    #     if usb_drives:
    #         usb_drive = usb_drives[0]
    #         with open(f"private_key.pem", "wb") as f:
    #             f.write(encrypted_private_key)

    #         print(f"🔑 Private key saved successfully to {usb_drive}/private_key.pem")


def save_public_key(public_key):
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