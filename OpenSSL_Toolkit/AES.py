# -*- coding: utf-8 -*-
"""
Created on Sat Dec  2 21:53:19 2023
@author: Rana Gamal
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

def aes_encrypt(plaintext, key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Ensure the key is 32 bytes (256 bits)
    key = key.ljust(32, b'\x00')[:32]

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Pad the plaintext and encrypt it
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

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
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext and unpad the result
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)

    # Return the result as binary data
    return plaintext

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
        file.write(decrypted_text)

'''
# Example usage:
plaintext = "Hello, AES encryption with OpenSSL in Python!"
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