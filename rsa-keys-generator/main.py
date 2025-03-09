import getpass
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key

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
    
    

if __name__ == "__main__":
    main()