from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

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

    h = SHA512.new(data)
    signature = pkcs1_15.new(key).sign(h)

    with open(output_path, 'wb') as signed_file:
        signed_file.write(data + signature)

def generate_key_pair_and_sign_file(file_to_sign='file_to_sign.txt'):

    signed_file_path = 'signed_file.bin'
    private_key_path = 'private.pem'

    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_key)

    with open('public.pem', 'wb') as public_file:
        public_file.write(public_key)

    print("RSA key pair generated successfully.")

    # Sign a file
    with open(file_to_sign, 'rb') as file:
        data = file.read()

    private_key = open(private_key_path, 'rb').read()
    key = RSA.import_key(private_key)

    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)

    with open(signed_file_path, 'wb') as signed_file:
        signed_file.write(data + signature)

    print("File signed successfully.")

# Example usage in a GUI:
# generate_key_pair_and_sign_file()
