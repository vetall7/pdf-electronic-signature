import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import secrets
import os

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

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(key) # AES-256-CBC
    )

    return private_key_bytes


def save_private_key(encrypted_private_key):
    media_dir = '/media'
    user = os.getlogin()
    media_dir = f'/media/{user}'
    if os.path.exists(media_dir):
        usb_drives = [os.path.join(media_dir, d) for d in os.listdir(media_dir)
                        if os.path.isdir(os.path.join(media_dir, d))]
        if usb_drives:
            usb_drive = usb_drives[0]
            with open(f"{usb_drive}/private_key.pem", "wb") as f:
                f.write(encrypted_private_key)

            print(f"🔑 Private key saved successfully to {usb_drive}/private_key.pem")


def save_public_key(public_key):
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("🔑 Public key saved successfully to public_key.pem")


# def list_usb_drives():
#     output = os.popen('lsblk -o NAME,SIZE,TYPE,MOUNTPOINT').readlines()

#     usb_drives = []
#     for line in output:
#         if 'usb' in line.lower() and 'part' in line.lower():
#             parts = line.split()
#             device = parts[0]
#             mountpoint = parts[-1] if len(parts) > 3 else None
#             usb_drives.append((device, mountpoint))

#     return usb_drives

# def select_usb_drive():
#     usb_drives = list_usb_drives()
#     if not usb_drives:
#         print("No USB drives connected.")
#         return None

#     selected_drive = inquirer.select(
#         message="Choose a USB drive:",
#         choices=usb_drives,
#     ).execute()

#     return selected_drive


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