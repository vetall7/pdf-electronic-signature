import tkinter as tk
from tkinter import filedialog
import os
from helper import sign_pdf, verify_pdf

def show_upload_button(mode):
    global selected_mode
    selected_mode = mode
    start_frame.pack_forget()
    upload_frame.pack()
    cancel_button.pack()

def upload_file():
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
    if pin_entry.get():
        go_button.pack()
    else:
        go_button.pack_forget()

def process_file(pin):
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
upload_button.pack()

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
