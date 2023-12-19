# -*- coding: utf-8 -*-
"""
Created on Mon Dec 11 22:11:23 2023

@author: Rana Gamal
"""

import tkinter as tk
from tkinter import filedialog
from AES import encrypt_file, decrypt_file
from codeRX import validate_signature
from codeTX import generate_key_pair, sign_file, generate_key_pair_and_sign_file
from Encrypt_and_sign import encrypt_and_sign
from decrypt_and_validate import decrypt_and_validate
import time

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenSSL Security Toolkit")
        self.root.geometry("500x500")
        
        # Set the application icon using iconphoto
        icon_path = "logo.png"
        self.set_icon(icon_path)

        # Create a PhotoImage object for the splash screen
        self.splash_image = tk.PhotoImage(file="logo.png")

        # Create a splash screen Label and set the image
        splash_label = tk.Label(self.root, image=self.splash_image)
        splash_label.pack()

        # Display the splash screen for a short delay
        self.root.after(2000, splash_label.destroy)

        # Welcoming message
        welcome_message = "Welcome to the OpenSSL Security Toolkit!"
        
        # Message area
        self.message_text = tk.Text(self.root, height=10, width=60)
        self.message_text.pack(pady=5)
        self.print_to_message_area(welcome_message)

        # AES Buttons
        self.encrypt_aes_button = tk.Button(root, text="Encrypt File (AES)", command=self.encrypt_aes_file, width=40, height=2)
        self.encrypt_aes_button.pack(pady=5)

        self.decrypt_aes_button = tk.Button(root, text="Decrypt File (AES)", command=self.decrypt_aes_file, width=40, height=2)
        self.decrypt_aes_button.pack(pady=5)
        
        # RSA Buttons
        self.generate_key_pair_button = tk.Button(root, text="Generate RSA Key Pair", command=self.generate_rsa_key_pair, width=40, height=2)
        self.generate_key_pair_button.pack(pady=5)

        self.sign_file_button = tk.Button(root, text="Sign File", command=self.sign_file_rsa, width=40, height=2)
        self.sign_file_button.pack(pady=5)

        self.generate_and_sign_button = tk.Button(root, text="Generate Key Pair and Sign File", command=self.generate_key_pair_and_sign_file, width=40, height=2)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Validate File", command=self.validate_rsa_file, width=40, height=2)
        self.verify_rsa_button.pack(pady=5)

        self.generate_and_sign_button = tk.Button(root, text="Encrypt and Sign", command=self.encrypt_and_sign, width=40, height=2)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Decrypt and Validate", command=self.decrypt_and_validate, width=40, height=2)
        self.verify_rsa_button.pack(pady=5)

    def print_to_message_area(self, message):
        self.message_text.insert(tk.END, message + "\n\n")
        self.message_text.see(tk.END)  # Scroll to the bottom to show the latest message

    def get_key(self):
        return self.key_entry.get().encode('utf-8')
    
    def encrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to encrypt (AES)")
        if input_file:
            # Prompt the user to enter the key
            key = self.prompt_for_key("AES Encryption")
            if not key:
                self.print_to_message_area("Warning: Please enter a key for AES encryption.")
                return  # Return early if the key is not provided

            # Perform encryption
            output_file = "Encrypted_File.txt"
            encrypt_file(input_file, output_file, key.encode('utf-8'))
            self.print_to_message_area(f"Encryption completed. Encrypted text written to {output_file}")

    def decrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to decrypt (AES)")
        if input_file:
            # Prompt the user to enter the key
            key = self.prompt_for_key("AES Decryption")
            if not key:
                self.print_to_message_area("Warning: Please enter a key for AES decryption.")
                return  # Return early if the key is not provided

            # Perform decryption
            output_file = "Decrypted_File.txt"
            decrypt_file(input_file, output_file, key.encode('utf-8'))
            self.print_to_message_area(f"Decryption completed. Decrypted text written to {output_file}")

    def prompt_for_key(self, title):
        return tk.simpledialog.askstring(title, "Enter Key:", show="*")

    def generate_rsa_key_pair(self):
        key_size = 2048  # You can adjust the key size as needed
        private_key_path, public_key_path = generate_key_pair(key_size)
        self.print_to_message_area(f"RSA Key Pair generated successfully.\nPrivate Key: {private_key_path}\nPublic Key: {public_key_path}")

    def generate_unique_filename(self, base_name, extension):
        timestamp = time.strftime("%Y%m%d%H%M%S")
        return f"{base_name}_{timestamp}.{extension}"

    def sign_file_rsa(self):
        file_to_sign = filedialog.askopenfilename(title="Select a file to sign", initialdir='.')
        if file_to_sign:
            private_key_path = filedialog.askopenfilename(title="Select the private key file")
            if private_key_path:
                output_path = self.generate_unique_filename('signed_file', 'bin')
                sign_file(file_to_sign, private_key_path, output_path)
                self.print_to_message_area(f"File signed successfully. Signed file saved to {output_path}")

    def generate_key_pair_and_sign_file(self):
        # Call the function from the imported module
        file_to_sign = 'file_to_sign.txt'
        file_to_sign = filedialog.askopenfilename(title="Select a file to sign", initialdir='.')
        self.print_to_message_area("Generating RSA key pair and signing file...")
        generate_key_pair_and_sign_file(file_to_sign)
        self.print_to_message_area("Process completed. Signed file saved to signed_file.bin")
            
    def validate_rsa_file(self):
        signed_file_path = filedialog.askopenfilename(title="Select a signed file to validate")
        if signed_file_path:
            self.print_to_message_area(validate_signature(signed_file_path, 'public.pem'))
    
    def encrypt_and_sign(self):
        self.print_to_message_area("Encrypting and signing file...")
        input_file = filedialog.askopenfilename(title="Select a file to encrypt and sign")
        if input_file:
            self.print_to_message_area(encrypt_and_sign(input_file))
            self.print_to_message_area("Process completed.")

    def decrypt_and_validate(self):
        self.print_to_message_area("Decrypting and validating file...")
        input_file = filedialog.askopenfilename(title="Select a file to encrypt and sign")
        if input_file:
            self.print_to_message_area(decrypt_and_validate(input_file))
            self.print_to_message_area("Process completed.")

    def set_icon(self, icon_path):
        try:
            icon_image = tk.PhotoImage(file=icon_path)
            self.root.iconphoto(True, icon_image)
        except tk.TclError:
            print(f"Error: Could not set icon. Check if {icon_path} exists and is a valid image file.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


