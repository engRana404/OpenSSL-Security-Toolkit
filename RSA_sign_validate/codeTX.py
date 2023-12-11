# codeTX.py

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('private.pem', 'wb') as private_file:
        private_file.write(private_key)

    with open('public.pem', 'wb') as public_file:
        public_file.write(public_key)

def sign_file(file_path, private_key_path, output_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    private_key = open(private_key_path, 'rb').read()
    key = RSA.import_key(private_key)

    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)

    with open(output_path, 'wb') as signed_file:
        signed_file.write(data + signature)

# Generate RSA key pair (run this only once)
generate_key_pair()

# Sign a file
file_to_sign = 'file_to_sign.txt'
signed_file_path = 'signed_file.bin'
private_key_path = 'private.pem'
sign_file(file_to_sign, private_key_path, signed_file_path)

print("File signed successfully.")
