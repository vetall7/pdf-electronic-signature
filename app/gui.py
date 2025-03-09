import tkinter as tk
from tkinter import filedialog, messagebox

def show_upload_button(mode):
    global selected_mode
    selected_mode = mode
    start_frame.pack_forget()
    upload_frame.pack()

def upload_file():
    file_path.set(filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")]))
    if file_path.get():
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

def process_file():
    if selected_mode == "sign" and not pin_entry.get():
        messagebox.showerror("Error", "Please enter a PIN")
        return
    # TODO: Implement signing and verification functionality
    go_button.pack_forget()
    pin_frame.pack_forget()
    status_label.config(text="Done!")
    status_label.pack()
    if selected_mode == "sign":
        download_button.pack()

def download_signed_pdf():
    # TODO: Implement download functionality
    messagebox.showinfo("Download", "Signed PDF downloaded successfully!")
    
root = tk.Tk()
root.title("PDF Sign & Verify")

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

go_button = tk.Button(root, text="Go!", command=process_file)

pin_frame = tk.Frame(root)
tk.Label(pin_frame, text="Enter PIN:").pack(side=tk.LEFT)
pin_entry = tk.Entry(pin_frame, show="*")
pin_entry.pack(side=tk.LEFT)
pin_entry.bind("<KeyRelease>", enable_go_button)

status_label = tk.Label(root, text="")

download_button = tk.Button(root, text="Download PDF", command=download_signed_pdf)

root.mainloop()
