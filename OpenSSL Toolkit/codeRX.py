# codeRX.py

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def validate_signature(file_path):
    public_key_path = 'public.pem'
    with open(file_path, 'rb') as file:
        received_data = file.read()

    data, received_signature = received_data[:-256], received_data[-256:]
    public_key = open(public_key_path, 'rb').read()

    h = SHA512.new(data)
    key = RSA.import_key(public_key)

    try:
        pkcs1_15.new(key).verify(h, received_signature)
        return"Signature is valid. Authentication successful."
    except (ValueError, TypeError):
        return"Signature is invalid. Authentication failed."

'''
# Validate the signature
signed_file_path = 'signed_file.bin'
public_key_path = 'public.pem'
validate_signature(signed_file_path, public_key_path)
'''
