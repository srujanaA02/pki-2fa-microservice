import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "student_private.pem"
ENCRYPTED_SEED_PATH = PROJECT_ROOT / "encrypted_seed.txt"
OUTPUT_SEED_PATH = PROJECT_ROOT / "seed.txt"

def load_private_key():
    """Load RSA private key from PEM file."""
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(f"Private key not found at {PRIVATE_KEY_PATH}")
    
    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return private_key

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256."""
    
    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)
    
    # 2. Decrypt with RSA/OAEP SHA-256
    decrypted_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 3. Decode to UTF-8
    decrypted_str = decrypted_bytes.decode("utf-8").strip()
    
    # 4. Validate 64-character hex
    if len(decrypted_str) != 64 or not all(c in "0123456789abcdef" for c in decrypted_str):
        raise ValueError(f"Decrypted seed is invalid: {decrypted_str}")
    
    return decrypted_str

if __name__ == "__main__":
    # Load private key
    private_key = load_private_key()
    
    # Read encrypted seed
    if not ENCRYPTED_SEED_PATH.exists():
        raise FileNotFoundError(f"{ENCRYPTED_SEED_PATH} not found. Run request_seed.py first.")
    
    encrypted_seed_b64 = ENCRYPTED_SEED_PATH.read_text().strip()
    
    # Decrypt
    seed = decrypt_seed(encrypted_seed_b64, private_key)
    
    # Save to seed.txt
    OUTPUT_SEED_PATH.write_text(seed, encoding="utf-8")
    print(f"Decrypted seed saved to: {OUTPUT_SEED_PATH}")
    print(f"Seed: {seed}")
