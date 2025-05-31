import os
import rsa
import smtplib
from tkinter import *
from tkinter import filedialog, messagebox
from email.message import EmailMessage
from cryptography.fernet import Fernet
from pathlib import Path

# Create folders if they don't exist
os.makedirs("keys", exist_ok=True)
os.makedirs("files", exist_ok=True)

# Initialize window
root = Tk()
root.geometry("792x447")
root.title("Secure File Transfer")
root.configure(bg="#444141")

# Functions

def generate_keys():
    public_key, private_key = rsa.newkeys(2048)
    with open("keys/public.pem", "wb") as pub_file:
        pub_file.write(public_key.save_pkcs1("PEM"))
    with open("keys/private.pem", "wb") as priv_file:
        priv_file.write(private_key.save_pkcs1("PEM"))
    messagebox.showinfo("Success", "Keys generated and saved in 'keys' folder")

def go_home():
    for widget in root.winfo_children():
        widget.destroy()
    show_home()

def browse_file(entry):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry.delete(0, END)
        entry.insert(0, file_path)

def send_encrypted():
    sender = sender_entry.get()
    password = password_entry.get()
    receiver = receiver_entry.get()
    pubkey_path = pubkey_entry.get()
    file_path = encfile_entry.get()

    if not all([sender, password, receiver, pubkey_path, file_path]):
        messagebox.showerror("Error", "All fields must be filled.")
        return

    try:
        key = Fernet.generate_key()
        fernet = Fernet(key)

        with open(file_path, "rb") as f:
            original = f.read()

        encrypted = fernet.encrypt(original)

        original_filename = Path(file_path).name
        encrypted_filename = f"files/{original_filename}.enc"
        with open(encrypted_filename, "wb") as f:
            f.write(encrypted)

        with open(pubkey_path, "rb") as f:
            pubkey = rsa.PublicKey.load_pkcs1(f.read())

        encrypted_key = rsa.encrypt(key, pubkey)
        encrypted_key_path = "files/encrypted_key.enc"
        with open(encrypted_key_path, "wb") as f:
            f.write(encrypted_key)

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = receiver
        msg["Subject"] = "Encrypted Files"
        msg.set_content("Attached are the encrypted file and key.")
        msg.make_mixed()

        with open(encrypted_filename, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="octet-stream", filename=Path(encrypted_filename).name)

        with open(encrypted_key_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="octet-stream", filename="encrypted_key.enc")

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)

        messagebox.showinfo("Success", "Encrypted file and key sent!")
        go_home()

    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email:\n{str(e)}")

def decrypt_file():
    encfile = decrypt_file_entry.get()
    enckey = decrypt_key_entry.get()
    privkey = decrypt_privkey_entry.get()
    sender = decrypt_sender_entry.get()
    password = decrypt_password_entry.get()
    receiver = decrypt_receiver_entry.get()

    if not all([encfile, enckey, privkey, sender, password, receiver]):
        messagebox.showerror("Error", "All fields must be filled.")
        return

    try:
        with open(enckey, "rb") as f:
            encrypted_key = f.read()
        with open(privkey, "rb") as f:
            priv_key = rsa.PrivateKey.load_pkcs1(f.read())
        key = rsa.decrypt(encrypted_key, priv_key)

        fernet = Fernet(key)
        with open(encfile, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)

        original_enc_filename = Path(encfile).name
        if original_enc_filename.endswith(".enc"):
            base_name = original_enc_filename[:-4]
        else:
            base_name = original_enc_filename

        decrypted_filename = f"dec_{base_name}"
        decrypted_path = os.path.join("files", decrypted_filename)

        with open(decrypted_path, "wb") as f:
            f.write(decrypted_data)

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = receiver
        msg["Subject"] = "Decrypted File"
        msg.set_content("Attached is the decrypted file.")

        with open(decrypted_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="octet-stream", filename=decrypted_filename)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)

        messagebox.showinfo("Success", f"Decrypted file sent as '{decrypted_filename}'!")
        go_home()

    except Exception as e:
        messagebox.showerror("Error", str(e))

def show_encrypt():
    for widget in root.winfo_children():
        widget.destroy()

    global sender_entry, password_entry, receiver_entry, pubkey_entry, encfile_entry

    Label(root, text="Sender email", fg="white", bg="#444141").grid(row=0, column=0, sticky=W, padx=10, pady=5)
    sender_entry = Entry(root, width=60)
    sender_entry.grid(row=0, column=1, padx=5)

    Label(root, text="App Password", fg="white", bg="#444141").grid(row=1, column=0, sticky=W, padx=10, pady=5)
    password_entry = Entry(root, width=60, show="*")
    password_entry.grid(row=1, column=1, padx=5)

    Label(root, text="Receiver email", fg="white", bg="#444141").grid(row=2, column=0, sticky=W, padx=10, pady=5)
    receiver_entry = Entry(root, width=60)
    receiver_entry.grid(row=2, column=1, padx=5)

    Label(root, text="Receiver public key", fg="white", bg="#444141").grid(row=3, column=0, sticky=W, padx=10, pady=5)
    pubkey_entry = Entry(root, width=50)
    pubkey_entry.grid(row=3, column=1, sticky=W)
    Button(root, text="Browse", command=lambda: browse_file(pubkey_entry)).grid(row=3, column=1, sticky=E)

    Label(root, text="File", fg="white", bg="#444141").grid(row=4, column=0, sticky=W, padx=10, pady=5)
    encfile_entry = Entry(root, width=50)
    encfile_entry.grid(row=4, column=1, sticky=W)
    Button(root, text="Browse", command=lambda: browse_file(encfile_entry)).grid(row=4, column=1, sticky=E)

    Button(root, text="Send Encrypted", bg="blue", fg="white", command=send_encrypted).grid(row=5, column=1, sticky=W, padx=10, pady=10)
    Button(root, text="Return", bg="red", fg="white", command=go_home).grid(row=5, column=1, sticky=E, padx=10, pady=10)

def show_decrypt():
    for widget in root.winfo_children():
        widget.destroy()

    global decrypt_file_entry, decrypt_key_entry, decrypt_privkey_entry
    global decrypt_sender_entry, decrypt_password_entry, decrypt_receiver_entry

    Label(root, text="Encrypted file", fg="white", bg="#444141").grid(row=0, column=0, sticky=W, padx=10, pady=5)
    decrypt_file_entry = Entry(root, width=50)
    decrypt_file_entry.grid(row=0, column=1, sticky=W)
    Button(root, text="Browse", command=lambda: browse_file(decrypt_file_entry)).grid(row=0, column=1, sticky=E)

    Label(root, text="Encrypted key", fg="white", bg="#444141").grid(row=1, column=0, sticky=W, padx=10, pady=5)
    decrypt_key_entry = Entry(root, width=50)
    decrypt_key_entry.grid(row=1, column=1, sticky=W)
    Button(root, text="Browse", command=lambda: browse_file(decrypt_key_entry)).grid(row=1, column=1, sticky=E)

    Label(root, text="Private key", fg="white", bg="#444141").grid(row=2, column=0, sticky=W, padx=10, pady=5)
    decrypt_privkey_entry = Entry(root, width=50)
    decrypt_privkey_entry.grid(row=2, column=1, sticky=W)
    Button(root, text="Browse", command=lambda: browse_file(decrypt_privkey_entry)).grid(row=2, column=1, sticky=E)

    Label(root, text="Sender email", fg="white", bg="#444141").grid(row=3, column=0, sticky=W, padx=10, pady=5)
    decrypt_sender_entry = Entry(root, width=60)
    decrypt_sender_entry.grid(row=3, column=1)

    Label(root, text="App Password", fg="white", bg="#444141").grid(row=4, column=0, sticky=W, padx=10, pady=5)
    decrypt_password_entry = Entry(root, width=60, show="*")
    decrypt_password_entry.grid(row=4, column=1)

    Label(root, text="Receiver email", fg="white", bg="#444141").grid(row=5, column=0, sticky=W, padx=10, pady=5)
    decrypt_receiver_entry = Entry(root, width=60)
    decrypt_receiver_entry.grid(row=5, column=1)

    Button(root, text="Decrypt File", bg="green", fg="white", command=decrypt_file).grid(row=6, column=1, sticky=W, padx=10, pady=10)
    Button(root, text="Return", bg="red", fg="white", command=go_home).grid(row=6, column=1, sticky=E, padx=10, pady=10)

def show_home():
    Button(root, text="Generate keys", bg="#cf4568", fg="black", width=20, height=2, command=generate_keys).place(x=330, y=100)
    Button(root, text="Send files", bg="#4f6ded", fg="black", width=20, height=2, command=show_encrypt).place(x=330, y=180)
    Button(root, text="Decrypt files", bg="#3fea55", fg="black", width=20, height=2, command=show_decrypt).place(x=330, y=260)

show_home()
root.mainloop()
