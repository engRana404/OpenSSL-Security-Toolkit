import hashlib
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

# Encrypt and sign the certificate
def encrypt_and_sign_certificate(certificate, aes_key, rsa_private_key):
    # Generate AES cipher
    cipher = AES.new(aes_key, AES.MODE_ECB)
    
    # Pad the certificate
    padded_certificate = pad(certificate.encode(), AES.block_size)
    
    # Encrypt the padded certificate using AES
    encrypted_certificate = cipher.encrypt(padded_certificate)
    
    # Generate SHA-512 hash of the encrypted certificate
    hash = SHA512.new(encrypted_certificate)
    
    # Sign the hash using RSA private key
    signer = pkcs1_15.new(rsa_private_key)
    signature = signer.sign(hash)
    
    return encrypted_certificate, signature

# Decrypt and validate the certificate
def decrypt_and_validate_certificate(encrypted_certificate, signature, aes_key, rsa_public_key):
    # Generate AES cipher
    cipher = AES.new(aes_key, AES.MODE_ECB)
    
    # Decrypt the encrypted certificate using AES
    padded_certificate = cipher.decrypt(encrypted_certificate)
    
    # Unpad the decrypted certificate
    decrypted_certificate = unpad(padded_certificate, AES.block_size).decode()
    
    # Generate SHA-512 hash of the encrypted certificate
    hash = SHA512.new(encrypted_certificate)
    
    # Verify the signature using RSA public key
    verifier = pkcs1_15.new(rsa_public_key)
    try:
        verifier.verify(hash, signature)
        is_valid = True
    except (ValueError, TypeError):
        is_valid = False
    
    return decrypted_certificate, is_valid

# Example usage
certificate = "This is my certificate"

# Generate AES key
aes_key = hashlib.sha512(b"my_secret_key").digest()[:32]  # 256-bit key for AES-256

# Generate RSA key pair
rsa_key = RSA.generate(2048)
rsa_private_key = rsa_key.export_key()
rsa_public_key = rsa_key.publickey()

# Encrypt and sign the certificate
encrypted_certificate, signature = encrypt_and_sign_certificate(certificate, aes_key, rsa_key)

# Decrypt and validate the certificate
decrypted_certificate, is_valid = decrypt_and_validate_certificate(encrypted_certificate, signature, aes_key, rsa_public_key)

# Print the results
print("Encrypted Certificate:", encrypted_certificate)
print("Signature:", signature.hex())
print("Decrypted Certificate:", decrypted_certificate)
print("Validation Result:",is_valid)
