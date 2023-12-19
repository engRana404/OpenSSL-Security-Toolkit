# codeRX.py

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Hash import SHA256

def validate_signature(file_path, public_key_path):
    with open(file_path, 'rb') as file:
        received_data = file.read()

    data, received_signature = received_data[:-256], received_data[-256:]
    public_key = open(public_key_path, 'rb').read()

    h = SHA256.new(data)
    key = RSA.import_key(public_key)

    try:
        pkcs1_15.new(key).verify(h, received_signature)
        return("Signature is valid. Authentication successful.")
    except (ValueError, TypeError):
        return("Signature is invalid. Authentication failed.")
