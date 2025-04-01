"""Helper functions for signing and verifying PDF files using RSA encryption.
@file: helper.py
@brief: This script provides functions to load RSA keys, sign a PDF file, and verify the signature.
@details: The script uses the PyPDF and cryptography libraries to handle PDF files and RSA encryption.
"""

import hashlib
import os
from tkinter import messagebox
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pypdf import PdfWriter, PdfReader

def find_pendrive():
    """"
    @brief: This function searches for a pendrive containing the private key.
    @details: It checks common mount points for the private key file.
    @return: The path to the private key file or None if not found.
    @note: The function assumes the file with private key is named "private_key.pem".
    """
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
    """"
    @brief: This function loads the private key from the pendrive.
    @details: It uses the provided PIN to decrypt the private key."
    @param pin: The PIN used to decrypt the private key.
    @return: The loaded private key or None if not found.
    """
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
    """"
    @brief: This function loads the public key from the specified path.
    @details: It checks if the public key file exists and loads it.
    @return: The loaded public key or None if not found.
    @note: The function assumes the file with public key is named "public_key.pem".
    """
    key_path = "../rsa-keys-generator/public_key.pem"
    if not os.path.exists(key_path):
        return
    with open(key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())
    

def sign_pdf(file_path, pin):
    """
    @brief: This function signs a PDF file using the private key.
    @details: It loads the private key, signs the PDF data, and saves the signed PDF with signature appended.
    @param file_path: The path to the PDF file to be signed.
    @param pin: The PIN used to decrypt the private key. 
    @return: True if the signing was successful, False otherwise.
    @note: The function saves signed PDF file with "_signed" suffix in the same folder.
    """

    private_key = load_private_key(pin)
    if not private_key:
        return False

    with open(file_path.get(), "rb") as pdf_file:
        pdf_data = pdf_file.read()

    signature = private_key.sign(pdf_data, padding.PKCS1v15(), hashes.SHA256())

    SIGNATURE_SIZE = 512
    
    padded_signature = signature.ljust(SIGNATURE_SIZE, b'\0')
    
    signed_pdf_path = file_path.get().replace(".pdf", "_signed.pdf")
    with open(signed_pdf_path, "wb") as signed_file:
        signed_file.write(pdf_data)
        signed_file.write(padded_signature)
    
    messagebox.showinfo("Success", f"Signed PDF saved as {signed_pdf_path}")
    return True

def verify_pdf(file_path):
    """
    @brief: This function verifies the signature of a signed PDF file.
    @details: It loads the public key, extracts the signature from the end of the file, and verifies it.
    @param file_path: The path to the signed PDF file.
    @return: True if the verification was successful, False otherwise.
    """
    public_key = load_public_key()
    if not public_key:
        return False
    
    with open(file_path.get(), "rb") as pdf_file:
        signed_data = pdf_file.read()
    
    SIGNATURE_SIZE = 512
    if len(signed_data) < SIGNATURE_SIZE:
        messagebox.showerror("Error", "File too small to contain signature")
        return False
    
    signature = signed_data[-SIGNATURE_SIZE:]
    #signature = signature.rstrip(b'\0')
    
    original_data = signed_data[:-SIGNATURE_SIZE]
    
    try:
        public_key.verify(
            signature,
            original_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        messagebox.showinfo("Success", "Signature verified successfully")
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Invalid signature: {str(e)}")
        return False