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

from sign_and_validate import encrypt_and_sign_certificate, decrypt_and_validate_certificate

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenSSL Security Toolkit")
        self.root.geometry("500x400")
        
        # Message area
        self.message_text = tk.Text(root, height=5, width=60)
        self.message_text.pack(pady=5)
        
        # Key Entry
        self.key_label = tk.Label(root, text="Enter Key:")
        self.key_label.pack(pady=5)

        self.key_entry = tk.Entry(root, show="*")
        self.key_entry.pack(pady=5)

        # Buttons
        self.encrypt_aes_button = tk.Button(root, text="Encrypt File (AES)", command=self.encrypt_aes_file)
        self.encrypt_aes_button.pack(pady=5)

        self.decrypt_aes_button = tk.Button(root, text="Decrypt File (AES)", command=self.decrypt_aes_file)
        self.decrypt_aes_button.pack(pady=5)

        self.sign_rsa_button = tk.Button(root, text="Sign and Encrypt File (RSA)", command=self.sign_and_encrypt_rsa_file)
        self.sign_rsa_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Decrypt and Verify File (RSA)", command=self.decrypt_and_verify_rsa_file)
        self.verify_rsa_button.pack(pady=5)
        

        # RSA Buttons
        self.generate_and_sign_button = tk.Button(root, text="Sign File (RSA)", command=self.generate_key_pair_and_sign_file)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Validate File (RSA)", command=self.validate_rsa_file)
        self.verify_rsa_button.pack(pady=5)

    def print_to_message_area(self, message):
        self.message_text.insert(tk.END, message + "\n")
        self.message_text.see(tk.END)  # Scroll to the bottom to show the latest message

    def get_key(self):
        return self.key_entry.get().encode('utf-8')

    def encrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to encrypt (AES)")
        if input_file:
            key = self.get_key()
            output_file = filedialog.asksaveasfilename(title="Save encrypted file (AES) as", defaultextension=".txt")
            if output_file:
                encrypt_file(input_file, output_file, key)
                self.print_to_message_area(f"Encryption completed. Encrypted text written to {output_file}")

    def decrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to decrypt (AES)")
        if input_file:
            key = self.get_key()
            output_file = filedialog.asksaveasfilename(title="Save decrypted file (AES) as", defaultextension=".txt")
            if output_file:
                decrypt_file(input_file, output_file, key)
                self.print_to_message_area(f"Decryption completed. Decrypted text written to {output_file}")


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
            self.print_to_message_area(validate_signature(signed_file_path))



    def sign_and_encrypt_rsa_file(self):
        file_to_sign = filedialog.askopenfilename(title="Select a file to sign and encrypt (RSA)")
        if file_to_sign:
            private_key_path = filedialog.askopenfilename(title="Select the private key file (RSA)")
            if private_key_path:
                signed_file_path = filedialog.asksaveasfilename(title="Save signed and encrypted file (RSA) as", defaultextension=".bin")
                if signed_file_path:
                    public_key_path = filedialog.askopenfilename(title="Select the public key file (RSA)")
                    if public_key_path:
                        encrypt_and_sign_certificate(file_to_sign, signed_file_path, public_key_path, private_key_path)
                        self.print_to_message_area("File signed and encrypted successfully.")

    def decrypt_and_verify_rsa_file(self):
        signed_file_path = filedialog.askopenfilename(title="Select a signed and encrypted file (RSA) to verify")
        if signed_file_path:
            public_key_path = filedialog.askopenfilename(title="Select the public key file (RSA)")
            if public_key_path:
                decrypted_file_path = filedialog.asksaveasfilename(title="Save decrypted and verified file (RSA) as", defaultextension=".txt")
                if decrypted_file_path:
                    private_key_path = filedialog.askopenfilename(title="Select the private key file (RSA)")
                    if private_key_path:
                        decrypt_and_validate_certificate(signed_file_path, decrypted_file_path, public_key_path, private_key_path)
                        self.print_to_message_area("File decrypted and verified successfully.")



if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


