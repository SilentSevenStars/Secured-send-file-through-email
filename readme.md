# Secure File Transfer using RSA, Fernet, and Email

This project is a **GUI-based Secure File Transfer System** built using Python. It allows users to:
- Generate RSA public/private key pairs
- Encrypt files with Fernet symmetric encryption
- Securely send the encrypted file and key via email using the recipient's RSA public key
- Decrypt received files using the sender's private key
- Re-send the decrypted file via email

## Features
- RSA-based key encryption (2048-bit)
- Fernet for file encryption (symmetric)
- Secure SMTP (SSL) email delivery
- GUI built with `tkinter`
- Organized file and key management in folders
- Cross-platform (Windows, Linux, Mac with Python)

## Requirements

Install Python packages:
pip install -r requirements.txt

## Run
![image alt](https://github.com/SilentSevenStars/Secured-send-file-through-email/blob/main/image/homepage.png?raw=true)

Step 1: Generate RSA Keys
Run the application:

python main.py
Click on "Generate keys".

Public and private keys will be saved in the keys/ folder as:

public.pem

private.pem

Step 2: Send Encrypted File
Click "Send files".

Fill in:

Sender email (Gmail recommended)

App password (NOT your normal password. Use Gmail App Passwords: https://myaccount.google.com/apppasswords)

Receiver email

Receiver's public key (select .pem file)

File to encrypt and send

Click "Send Encrypted".

The file is encrypted, a random Fernet key is generated, and the key is encrypted using RSA. Both the encrypted file and key are emailed to the recipient.

![image alt](https://github.com/SilentSevenStars/Secured-send-file-through-email/blob/main/image/encryptpage.png?raw=true)

Step 3: Decrypt Received File
Click "Decrypt files".

Fill in:

Encrypted file (downloaded .enc file)

Encrypted key (downloaded encrypted_key.enc)

Private key (your private.pem)

Sender email (the one you're sending FROM)

App password (Gmail app password)

Receiver email (who should receive the decrypted file)

Click "Decrypt File".

The system decrypts the key and file, and sends the result via email.

![image alt](https://github.com/SilentSevenStars/Secured-send-file-through-email/blob/main/image/decryptpage.png?raw=true)

## Members
Joseph Matthew Ringor - Leader

Ejay Basinga

Aaron John Palad

