import os
from tkinter import messagebox
import PyPDF2
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization

def find_pendrive():
    possible_mounts = ["/media", "/mnt", "E:/", "F:/", "G:/"]
    for mount in possible_mounts:
        if os.path.exists(mount):
            for subdir in os.listdir(mount):
                key_path = os.path.join(mount, subdir, "private_key.pem")
                if os.path.exists(key_path):
                    return key_path
    return None

def load_private_key():
    key_path = find_pendrive()
    if not key_path:
        messagebox.showerror("Error", "Pendrive with private key not found")
        return
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key():
    key_path = "../rsa-keys-generator/public_key.pem"
    if not os.path.exists(key_path):
        messagebox.showerror("Error", "Public key not found in application directory")
        return
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def sign_pdf(file_path):
    private_key = load_private_key()
    if not private_key:
        return False
    with open(file_path.get(), "rb") as pdf_file:
        pdf_data = pdf_file.read()
    signature = private_key.sign(pdf_data, padding.PKCS1v15(), hashes.SHA256())
    signed_pdf_path = file_path.get().replace(".pdf", "_signed.pdf")
    with open(signed_pdf_path, "wb") as signed_file:
        signed_file.write(pdf_data + b"\n" + signature)
    messagebox.showinfo("Success", f"Signed PDF saved as {signed_pdf_path}")
    return True

def verify_pdf(file_path):
    public_key = load_public_key()
    if not public_key:
        return False
    with open(file_path.get(), "rb") as pdf_file:
        content = pdf_file.read().rsplit(b"\n", 1)
    if len(content) < 2:
        messagebox.showerror("Error", "Invalid signed PDF format")
        return False
    pdf_data, signature = content
    try:
        public_key.verify(signature, pdf_data, padding.PKCS1v15(), hashes.SHA256())
        messagebox.showinfo("Success", "Signature is valid")
        return True
    except Exception:
        messagebox.showerror("Error", "Invalid signature")
        return False
