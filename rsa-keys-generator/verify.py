import getpass
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from main import transform_pin_to_key_256

pin = getpass.getpass("Enter your pin: ")
hashed_pin = transform_pin_to_key_256(pin)

message = b"Test message to sign"
signature = None

with open("private_key.pem", "rb") as f:
    try:
        private_key = serialization.load_pem_private_key(f.read(), password=hashed_pin)
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("message signed")
    except ValueError:
        print("Invalid password")
        exit(1)


with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("signature verified")
    except InvalidSignature:
        print("Invalid signature")