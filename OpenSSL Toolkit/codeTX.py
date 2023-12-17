from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_key_pair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    private_key_path = 'private.pem'
    public_key_path = 'public.pem'

    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_key)

    with open(public_key_path, 'wb') as public_file:
        public_file.write(public_key)

    return private_key_path, public_key_path

def sign_file(file_path, private_key_path, output_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    private_key = open(private_key_path, 'rb').read()
    key = RSA.import_key(private_key)

    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)

    with open(output_path, 'wb') as signed_file:
        signed_file.write(data + signature)

def generate_key_pair_and_sign_file(file_to_sign='file_to_sign.txt'):
    private_key_path, _ = generate_key_pair()
    signed_file_path = 'signed_file.bin'

    sign_file(file_to_sign, private_key_path, signed_file_path)
    print("File signed successfully.")

# Example usage
generate_key_pair_and_sign_file()
