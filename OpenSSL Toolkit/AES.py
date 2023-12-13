# -*- coding: utf-8 -*-
"""
Created on Sat Dec  2 21:53:19 2023

@author: Rana Gamal
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os

def aes_encrypt(plaintext, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Ensure the key is 32 bytes (256 bits)
    key = key.ljust(32, b'\x00')[:32]

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Pad the plaintext and encrypt it
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine the IV and ciphertext and return the result as a base64-encoded string
    return b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    # Decode the base64-encoded input string
    ciphertext = b64decode(ciphertext)

    # Extract the IV from the ciphertext
    iv = ciphertext[:16]

    # Ensure the key is 32 bytes (256 bits)
    key = key.ljust(32, b'\x00')[:32]

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    # Decrypt the ciphertext and unpad the result
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    # Return the result as a UTF-8 encoded string
    return plaintext.decode('utf-8')

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        plaintext = file.read()
    
    encrypted_text = aes_encrypt(plaintext, key)

    with open(output_file, 'w') as file:
        file.write(encrypted_text)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'r') as file:
        encrypted_text = file.read()

    decrypted_text = aes_decrypt(encrypted_text, key)

    with open(output_file, 'wb') as file:
        file.write(decrypted_text.encode('utf-8'))

'''
# Example usage:
plaintext = "Hello, AES encryption with cryptography library in Python!"
key = b'SecretKey123456'  # Replace this with your actual key

# Encryption
encrypted_text = aes_encrypt(plaintext.encode('utf-8'), key)
print(f"Encrypted text: {encrypted_text}" + "\n")

# Decryption
decrypted_text = aes_decrypt(encrypted_text, key)
print(f"Decrypted text: {decrypted_text}" + "\n")

# Example usage:
plaintext_input_file = "Input.txt"
encrypted_output_file = "Output.txt"
decrypted_output_file = "DOutput.txt"

# Encryption
encrypt_file(plaintext_input_file, encrypted_output_file, key)
print(f"Encryption completed. Encrypted text written to {encrypted_output_file}" + "\n")

# Decryption
decrypt_file(encrypted_output_file, decrypted_output_file, key)
print(f"Decryption completed. Decrypted text written to {decrypted_output_file}" + "\n")
'''