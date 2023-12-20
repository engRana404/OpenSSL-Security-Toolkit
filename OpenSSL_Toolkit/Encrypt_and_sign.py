from codeTX import sign_file, generate_key_pair
from AES import encrypt_file

def encrypt_and_sign(file_to_sign, key):
    # Call the generate_key_pair function to handle key generation or input
    generate_key_pair()

    # Sign a file
    signed_file_path = 'signed_file.bin'
    private_key_path = 'private.pem'
    public_key_path = 'public.pem'
    sign_file(file_to_sign, private_key_path, signed_file_path)

    # Encryption
    plaintext_input_file = signed_file_path
    encrypted_output_file = 'encrypted_output.txt'
    
    encrypt_file(plaintext_input_file, encrypted_output_file, key)

    return(f"Encryption completed. Encrypted text written to {encrypted_output_file}")


