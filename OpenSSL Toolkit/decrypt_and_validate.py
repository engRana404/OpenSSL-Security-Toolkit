from AES import decrypt_file
from codeRX import validate_signature

def decrypt_and_validate():
    private_key_path = 'private.pem'
    public_key_path = 'public.pem'
    
    # Decryption
    encrypted_file = 'encrypted_output.txt'
    decrypted_file = 'decrypted.bin'
    key = b'SecretKey123456'  # Replace with your actual encryption key
    
    decrypted_binary_data = decrypt_file(encrypted_file, decrypted_file, key)
    
    print("File decrypted")
    
    # Validation
    return validate_signature(decrypted_file, public_key_path)

#decrypt_and_validate()

