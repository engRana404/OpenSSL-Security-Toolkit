from AES import decrypt_file
from codeRX import validate_signature

def decrypt_and_validate(encrypted_file, key):
    private_key_path = 'private.pem'
    public_key_path = 'public.pem'
    
    # Decryption
    decrypted_file = 'decrypted.bin'
    
    decrypt_file(encrypted_file, decrypted_file, key)
    
    # Validation
    return ((f"Encryption completed. Encrypted text written to {decrypted_file}" + "\n\n") + validate_signature(decrypted_file, public_key_path)) 
