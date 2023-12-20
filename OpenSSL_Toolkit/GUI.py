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

        # Create a PhotoImage object for the splash screen
        self.create_splash_screen()

        # Initialize message area
        self.message_text = tk.Text(self.root, height=10, width=60)
        self.message_text.pack(pady=5)

        # Welcoming message
        welcome_message = "Welcome to the OpenSSL Security Toolkit!"
        
        # Message area
        self.print_to_message_area(welcome_message)

        # AES Buttons
        self.encrypt_aes_button = tk.Button(root, text="Encrypt File (AES)", command=self.encrypt_aes_file, width=40, height=1)
        self.encrypt_aes_button.pack(pady=5)

        self.decrypt_aes_button = tk.Button(root, text="Decrypt File (AES)", command=self.decrypt_aes_file, width=40, height=1)
        self.decrypt_aes_button.pack(pady=5)
        
        # RSA Buttons
        self.generate_key_pair_button = tk.Button(root, text="Generate RSA Key Pair", command=self.generate_rsa_key_pair, width=40, height=1)
        self.generate_key_pair_button.pack(pady=5)

        self.sign_file_button = tk.Button(root, text="Sign File", command=self.sign_file_rsa, width=40, height=1)
        self.sign_file_button.pack(pady=5)

        self.generate_and_sign_button = tk.Button(root, text="Generate Key Pair and Sign File", command=self.generate_key_pair_and_sign_file, width=40, height=1)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Validate File", command=self.validate_rsa_file, width=40, height=1)
        self.verify_rsa_button.pack(pady=5)

        self.generate_and_sign_button = tk.Button(root, text="Encrypt and Sign", command=self.encrypt_and_sign, width=40, height=1)
        self.generate_and_sign_button.pack(pady=5)

        self.verify_rsa_button = tk.Button(root, text="Decrypt and Validate", command=self.decrypt_and_validate, width=40, height=1)
        self.verify_rsa_button.pack(pady=5)

    def print_to_message_area(self, message):
        self.message_text.insert(tk.END, message + "\n\n")
        self.message_text.see(tk.END)  # Scroll to the bottom to show the latest message

    def get_key(self):
        return self.key_entry.get().encode('utf-8')
    
    def encrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to encrypt (AES)")
        if not input_file:
            self.print_to_message_area("Warning: No file selected for encryption.")
            return

        key = self.prompt_for_key("AES Encryption")
        if not key:
            self.print_to_message_area("Warning: Please enter a key for AES encryption.")
            return

        try:
            output_file = "Encrypted_File.txt"
            encrypt_file(input_file, output_file, key.encode('utf-8'))
            self.print_to_message_area(f"Encryption completed. Encrypted text written to {output_file}")
        except Exception as e:
            self.print_to_message_area(f"Error during encryption: {str(e)}")

    def decrypt_aes_file(self):
        input_file = filedialog.askopenfilename(title="Select a file to decrypt (AES)")
        if not input_file:
            self.print_to_message_area("Warning: No file selected for decryption.")
            return

        key = self.prompt_for_key("AES Decryption")
        if not key:
            self.print_to_message_area("Warning: Please enter a key for AES decryption.")
            return

        try:
            output_file = "Decrypted_File.txt"
            decrypt_file(input_file, output_file, key.encode('utf-8'))
            self.print_to_message_area(f"Decryption completed. Decrypted text written to {output_file}")
        except Exception as e:
            self.print_to_message_area(f"Error during decryption: {str(e)}")

    def prompt_for_key(self, title):
        return tk.simpledialog.askstring(title, "Enter an AES Key:", show="*")

    def generate_rsa_key_pair(self):
        try:
            key_size = 2048  # You can adjust the key size as needed
            private_key_path, public_key_path = generate_key_pair(key_size)
            self.print_to_message_area(f"RSA Key Pair generated successfully.\nPrivate Key: {private_key_path}\nPublic Key: {public_key_path}")
        except Exception as e:
            self.print_to_message_area(f"Error generating RSA Key Pair: {str(e)}")

    def generate_unique_filename(self, base_name, extension):
        timestamp = time.strftime("%Y%m%d%H%M%S")
        return f"{base_name}_{timestamp}.{extension}"

    def sign_file_rsa(self):
        try:
            file_to_sign = filedialog.askopenfilename(title="Select a file to sign", initialdir='.')
            if not file_to_sign:
                self.print_to_message_area("Warning: No file selected for signing.")
                return

            private_key_path = filedialog.askopenfilename(title="Select the private key file")
            if not private_key_path:
                self.print_to_message_area("Warning: No private key file selected for signing.")
                return

            output_path = self.generate_unique_filename('signed_file', 'bin')
            sign_file(file_to_sign, private_key_path, output_path)
            self.print_to_message_area(f"File signed successfully. Signed file saved to {output_path}")
        except Exception as e:
            self.print_to_message_area(f"Error during signing: {str(e)}")

    def generate_key_pair_and_sign_file(self):
        try:
            file_to_sign = 'file_to_sign.txt'
            file_to_sign = filedialog.askopenfilename(title="Select a file to sign", initialdir='.')
            self.print_to_message_area("Generating RSA key pair and signing file...")
            generate_key_pair_and_sign_file(file_to_sign)
            self.print_to_message_area("Process completed. Signed file saved to signed_file.bin")
        except Exception as e:
            self.print_to_message_area(f"Error generating key pair and signing file: {str(e)}")
            
    def validate_rsa_file(self):
        try:
            signed_file_path = filedialog.askopenfilename(title="Select a signed file to validate")
            if not signed_file_path:
                self.print_to_message_area("Warning: No signed file selected for validation.")
                return

            validation_result = validate_signature(signed_file_path, 'public.pem')
            self.print_to_message_area(validation_result)
        except Exception as e:
            self.print_to_message_area(f"Error during validation: {str(e)}")

    def encrypt_and_sign(self):
        try:
            self.print_to_message_area("Encrypting and signing file...")
            input_file = filedialog.askopenfilename(title="Select a file to encrypt and sign")
            if not input_file:
                self.print_to_message_area("Warning: No file selected for encryption and signing.")
                return

            key = self.prompt_for_key("AES Encryption")
            if not key:
                self.print_to_message_area("Warning: Please enter a key for AES encryption.")
                return

            encrypted_and_signed_message = encrypt_and_sign(input_file, key.encode('utf-8'))
            self.print_to_message_area(encrypted_and_signed_message)
            self.print_to_message_area("Process completed.")
        except Exception as e:
            self.print_to_message_area(f"Error during encryption and signing: {str(e)}")

    def decrypt_and_validate(self):
        try:
            self.print_to_message_area("Decrypting and validating file...")
            input_file = filedialog.askopenfilename(title="Select a file to decrypt and validate")
            if not input_file:
                self.print_to_message_area("Warning: No file selected for decryption and validation.")
                return

            key = self.prompt_for_key("AES Decryption")
            if not key:
                self.print_to_message_area("Warning: Please enter a key for AES decryption.")
                return

            decrypted_and_validated_message = decrypt_and_validate(input_file, key.encode('utf-8'))
            self.print_to_message_area(decrypted_and_validated_message)
            self.print_to_message_area("Process completed.")
        except Exception as e:
            self.print_to_message_area(f"Error during decryption and validation: {str(e)}")

    def create_splash_screen(self):
        try:
            self.splash_image = tk.PhotoImage(file="logo.png")
        except tk.TclError as e:
            error_message = f"Warning: Could not load splash image. {str(e)}"
            print(error_message)
            self.splash_image = None  # Set splash_image to None when the image is not found
            return  # Skip the creation of the splash screen

        # Create a splash screen Label and set the image if available
        splash_label = tk.Label(self.root, image=self.splash_image)
        splash_label.pack()

        # Display the splash screen for a short delay
        self.root.after(2000, splash_label.destroy)



if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


