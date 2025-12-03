import base64

# Step 1: Base64 decode the encrypted seed string
def base64_decode(encrypted_seed_b64: str) -> bytes:
    return base64.b64decode(encrypted_seed_b64)

# Step 2: RSA/OAEP decrypt with SHA-256
def rsa_oaep_decrypt(encrypted_bytes: bytes, private_key) -> bytes:
    # Import here to avoid dependency if not using this function
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    return private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Step 3: Decode bytes to UTF-8 string
def bytes_to_utf8(decrypted_bytes: bytes) -> str:
    return decrypted_bytes.decode('utf-8')

# Step 4: Validate 64-character hex string
def validate_hex_seed(hex_seed: str) -> bool:
    # Check length is 64
    if len(hex_seed) != 64:
        return False
    
    # Check all characters are in '0123456789abcdef'
    valid_chars = set('0123456789abcdef')
    return all(c in valid_chars for c in hex_seed.lower())

# Main decrypt_seed function (as per your instructions)
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP
    
    Args:
        encrypted_seed_b64: Base64-encoded ciphertext
        private_key: RSA private key object
    
    Returns:
        Decrypted hex seed (64-character string)
    """
    # Implementation:
    # 1. Base64 decode the encrypted seed string
    encrypted_bytes = base64_decode(encrypted_seed_b64)
    
    # 2. RSA/OAEP decrypt with SHA-256
    decrypted_bytes = rsa_oaep_decrypt(encrypted_bytes, private_key)
    
    # 3. Decode bytes to UTF-8 string
    hex_seed = bytes_to_utf8(decrypted_bytes)
    
    # 4. Validate: must be 64-character hex string
    if not validate_hex_seed(hex_seed):
        raise ValueError("Invalid hex seed format")
    
    # 5. Return hex seed
    return hex_seed

# Helper function to load private key
def load_private_key_from_file(filename: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend
    
    with open(filename, 'rb') as f:
        private_key_data = f.read()
    
    return load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )

# Test the function
if __name__ == "__main__":
    # Load your private key
    private_key = load_private_key_from_file("student_private.pem")
    
    # Read encrypted seed from file
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()
    
    # Decrypt the seed
    try:
        hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
        print("Decrypted seed:", hex_seed)
        
        # Save to /data/seed.txt (for later use in container)
        with open("seed.txt", "w") as f:
            f.write(hex_seed)
        print("Seed saved to seed.txt")
        
    except Exception as e:
        print("Decryption failed:", str(e))
