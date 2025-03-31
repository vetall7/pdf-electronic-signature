"""
@file: gui.py
@brief: This script provides a GUI for signing and verifying PDF files using RSA keys.
@details: The GUI allows users to select a PDF file, enter a PIN for signing, and verify the signature.
"""
import tkinter as tk
from tkinter import filedialog
import os
from helper import *

def show_upload_button(mode):
    """
    @brief: This function is called when the user selects a mode (sign or verify).
    @details: It updates the GUI to show the upload button and checks for the presence of the required keys.
    """

    global selected_mode
    selected_mode = mode
    start_frame.pack_forget()

    for widget in upload_frame.winfo_children():
        if isinstance(widget, tk.Label):
            widget.destroy()
        
    upload_button.config(state=tk.NORMAL)

    if selected_mode == "sign":
        is_pendrive_detected = find_pendrive()
        if is_pendrive_detected is None:
            upload_button.config(state=tk.DISABLED)
            message_label = tk.Label(upload_frame, text="Pendrive with private key is not detected.", fg="red") 
        else:
            message_label = tk.Label(upload_frame, text="Pendrive with private key is detected.", fg="green")
    if selected_mode == "verify":
        is_public_key_detected = load_public_key()
        if is_public_key_detected is None:
            upload_button.config(state=tk.DISABLED)
            message_label = tk.Label(upload_frame, text="Public key is not detected. (../rsa-keys-generator/public_key.pem)", fg="red")
        else:
            message_label = tk.Label(upload_frame, text="Public key is detected.", fg="green")
          
    upload_button.pack(pady=5)
    message_label.pack(pady=15)      
    upload_frame.pack()
    cancel_button.pack()

def upload_file():
    """
    @brief: This function is called when the user clicks the upload button.
    @details: It opens a file dialog to select a PDF file and updates the GUI accordingly.
    """
    file_path.set(filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")]))
    if file_path.get():
        file_label.config(text=f"Selected file: {os.path.basename(file_path.get())}")
        file_label.pack()
        upload_frame.pack_forget()
        if selected_mode == "sign":
            pin_frame.pack()
        else:
            go_button.pack()

def enable_go_button(*args):
    """
    @brief: This function is called when the user types in the PIN entry field.
    @details: It enables or disables the Go button based on whether the PIN entry is empty or not.
    """
    if pin_entry.get():
        go_button.pack()
    else:
        go_button.pack_forget()

def process_file(pin):
    """
    @brief: This function is called when the user clicks the Go button.
    @details: It processes the selected PDF file based on the selected mode (sign or verify).
    @param pin: The PIN entered by the user for signing the PDF file."""
    status = None
    if selected_mode == "sign":
        status = sign_pdf(file_path, pin)
    else:
        status = verify_pdf(file_path)
    
    if not status:
        cancel_action()
        return

    go_button.pack_forget()
    pin_frame.pack_forget()
    status_label.config(text="Done!")
    status_label.pack()
    
def cancel_action():
    """
    @brief: This function is called when the user clicks the Cancel button.
    @details: It resets the GUI to its initial state and clears the selected file and PIN entry."""

    upload_frame.pack_forget()
    go_button.pack_forget()
    pin_frame.pack_forget()
    status_label.pack_forget()
    cancel_button.pack_forget()
    file_label.pack_forget()
    start_frame.pack()
    file_path.set("")
    pin_entry.delete(0, tk.END)
    status_label.config(text="")
    file_label.config(text="")

root = tk.Tk()
root.title("PDF Sign & Verify")
root.geometry("400x150")

file_path = tk.StringVar()
selected_mode = None

start_frame = tk.Frame(root)
sign_button = tk.Button(start_frame, text="Signing PDF", command=lambda: show_upload_button("sign"))
verify_button = tk.Button(start_frame, text="Signature verification", command=lambda: show_upload_button("verify"))
sign_button.pack(pady=5)
verify_button.pack(pady=5)
start_frame.pack()

upload_frame = tk.Frame(root)
upload_button = tk.Button(upload_frame, text="Upload PDF", command=upload_file)

file_label = tk.Label(root, text="")

pin_frame = tk.Frame(root)
tk.Label(pin_frame, text="Enter PIN:").pack(side=tk.LEFT)
pin_entry = tk.Entry(pin_frame, show="*")
pin_entry.pack(side=tk.LEFT)
pin_entry.bind("<KeyRelease>", enable_go_button)


go_button = tk.Button(root, text="Go", command=lambda: process_file(pin_entry.get()))


status_label = tk.Label(root, text="")

cancel_button = tk.Button(root, text="Cancel", command=cancel_action)
root.mainloop()
