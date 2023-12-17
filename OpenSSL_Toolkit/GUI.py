# -*- coding: utf-8 -*-
"""
Created on Mon Dec 11 22:11:23 2023

@author: DELL 3550
"""
import tkinter as tk
from tkinter import filedialog
from AES import encrypt_file, decrypt_file
from codeRX import validate_signature
from codeTX import generate_key_pair_and_sign_file
from Encrypt_and_sign import encrypt_and_sign
from decrypt_and_validate import decrypt_and_validate

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenSSL Security Toolkit")
        self.root.geometry("500x300")
        
        # Message area
        self.message_text = tk.Text(root, height=5, width=60)
        self.message_text.pack(pady=5)
        
        '''
        # Key Entry
        self.key_label = tk.Label(root, text="Enter Key:")
        self.key_label.pack(pady=5)

        self.key_entry = tk.Entry(root, show="*")
        self.key_entry.pack(pady=5)'''

        # AES Buttons
        self.encrypt_aes_button = tk.Button(root, text="Encrypt File (AES)", command=self.encrypt_aes_file)
        self.encrypt_aes_button.pack(pady=5)

        self.decrypt_aes_button = tk.Button(root, text="Decrypt File (AES)", command=self.decrypt_aes_file)
        self.decrypt_aes_button.pack(pady=5)
        

        # RSA Buttons

        self.generate_and_sign_button = tk.Button(root, text="Sign File", command=self.generate_key_pair_and_sign_file)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Validate File", command=self.validate_rsa_file)
        self.verify_rsa_button.pack(pady=5)

        self.generate_and_sign_button = tk.Button(root, text="Encrypt and Sign", command=self.encrypt_and_sign)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Decrypt and Validate", command=self.decrypt_and_validate)
        self.verify_rsa_button.pack(pady=5)

    def print_to_message_area(self, message):
        self.message_text.insert(tk.END, message + "\n")
        self.message_text.see(tk.END)  # Scroll to the bottom to show the latest message

    def get_key(self):
        return self.key_entry.get().encode('utf-8')
    
    def encrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to encrypt (AES)")
        if input_file:
            # Prompt the user to enter the key
            key = self.prompt_for_key("AES Encryption")
            if key:
                # Perform encryption
                output_file = filedialog.asksaveasfilename(title="Save encrypted file (AES) as", defaultextension=".txt")
                if output_file:
                    encrypt_file(input_file, output_file, key.encode('utf-8'))
                    self.print_to_message_area(f"Encryption completed. Encrypted text written to {output_file}")

    def decrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to decrypt (AES)")
        if input_file:
            # Prompt the user to enter the key
            key = self.prompt_for_key("AES Decryption")
            if key:
                # Perform decryption
                output_file = filedialog.asksaveasfilename(title="Save decrypted file (AES) as", defaultextension=".txt")
                if output_file:
                    decrypt_file(input_file, output_file, key.encode('utf-8'))
                    self.print_to_message_area(f"Decryption completed. Decrypted text written to {output_file}")

    def prompt_for_key(self, title):
        return tk.simpledialog.askstring(title, "Enter Key:", show="*")


    def generate_key_pair_and_sign_file(self):
        # Call the function from the imported module
        file_to_sign = 'file_to_sign.txt'
        file_to_sign = filedialog.askopenfilename(title="Select a file to sign (RSA)", initialdir='.')
        self.print_to_message_area("Generating RSA key pair and signing file...")
        generate_key_pair_and_sign_file(file_to_sign)
        self.print_to_message_area("Process completed.")
            
    def validate_rsa_file(self):
        signed_file_path = filedialog.askopenfilename(title="Select a signed file (RSA) to validate")
        if signed_file_path:
            self.print_to_message_area(validate_signature(signed_file_path, 'public.pem'))
    
    def encrypt_and_sign(self):
        self.print_to_message_area("Encrypting and signing file...")
        self.print_to_message_area(encrypt_and_sign())
        self.print_to_message_area("Process completed.")

    def decrypt_and_validate(self):
        self.print_to_message_area("Decrypting and validating file...")
        self.print_to_message_area(decrypt_and_validate())
        self.print_to_message_area("Process completed.")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


