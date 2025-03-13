import base64
import hashlib
import os
from tkinter import messagebox
import PyPDF2
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from pypdf import PdfWriter, PdfReader

def find_pendrive():
    user_name = os.getlogin()
    possible_mounts = ["/media/" + user_name, "/mnt", "E:/", "F:/", "G:/"]
    for mount in possible_mounts:
        if os.path.exists(mount):
            for subdir in os.listdir(mount):
                key_path = os.path.join(mount, subdir, "private_key.pem")
                if os.path.exists(key_path):
                    return key_path
    return None

def load_private_key(pin):
    key_path = find_pendrive()
    if not key_path:
        messagebox.showerror("Error", "Pendrive with private key not found")
        return
    with open(key_path, "rb") as key_file:
        try:
            return serialization.load_pem_private_key(key_file.read(), password=hashlib.sha256(pin.encode()).digest())
        except Exception:
            messagebox.showerror("Error", "Invalid PIN")
            return

def load_public_key():
    key_path = "../rsa-keys-generator/public_key.pem"
    if not os.path.exists(key_path):
        messagebox.showerror("Error", "Public key not found in application directory")
        return
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def sign_pdf(file_path, pin):
    private_key = load_private_key(pin)
    if not private_key:
        return False

    reader = PdfReader(file_path.get())

    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    pdf_data = b"".join(reader.pages[0].extract_text().encode('utf-8') for _ in reader.pages)

    signature = private_key.sign(pdf_data, padding.PKCS1v15(), hashes.SHA256())
    
    writer.add_attachment("signature", signature)

    signed_pdf_path = file_path.get().replace(".pdf", "_signed.pdf")
    with open(signed_pdf_path, "wb") as signed_file:
        writer.write(signed_file)
    messagebox.showinfo("Success", f"Signed PDF saved as {signed_pdf_path}")
    return True

def verify_pdf(file_path):
    public_key = load_public_key()
    if not public_key:
        return False
    
    reader = PdfReader(file_path.get())

    pdf_data = b"".join(reader.pages[0].extract_text().encode('utf-8') for _ in reader.pages)

    try:
        signature = reader.attachments["signature"][0]
    except KeyError:
        messagebox.showerror("Error", "No signature found in PDF")
        return False

    try:
        public_key.verify(
            signature,
            pdf_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature verified successfully")
        return True
    except Exception as e:
        messagebox.showerror("Error", "Invalid signature")
        return False
