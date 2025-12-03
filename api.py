from fastapi import FastAPI, HTTPException
import base64
import os
import time

app = FastAPI()

# Endpoint 1: POST /decrypt-seed
@app.post("/decrypt-seed")
def decrypt_seed_endpoint(data: dict):
    try:
        encrypted_seed = data.get("encrypted_seed")
        
        if not encrypted_seed:
            raise HTTPException(status_code=400, detail="Missing encrypted_seed")
        
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        
        with open("student_private.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        encrypted_bytes = base64.b64decode(encrypted_seed)
        
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        hex_seed = decrypted_bytes.decode('utf-8')
        
        if len(hex_seed) != 64:
            raise ValueError("Invalid seed length")
        
        os.makedirs("/data", exist_ok=True)
        with open("/data/seed.txt", "w") as f:
            f.write(hex_seed)
        
        return {"status": "ok"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed")

# Endpoint 2: GET /generate-2fa
@app.get("/generate-2fa")
def generate_2fa():
    try:
        if not os.path.exists("/data/seed.txt"):
            raise HTTPException(status_code=500, detail="Seed not decrypted yet")
        
        with open("/data/seed.txt", "r") as f:
            hex_seed = f.read().strip()
        
        import base64 as b64
        import pyotp
        
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = b64.b32encode(seed_bytes).decode('utf-8')
        
        totp = pyotp.TOTP(base32_seed)
        code = totp.now()
        
        current_time = int(time.time())
        valid_for = 30 - (current_time % 30)
        
        return {"code": code, "valid_for": valid_for}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

# Endpoint 3: POST /verify-2fa
@app.post("/verify-2fa")
def verify_2fa(data: dict):
    try:
        code = data.get("code")
        
        if not code:
            raise HTTPException(status_code=400, detail="Missing code")
        
        if not os.path.exists("/data/seed.txt"):
            raise HTTPException(status_code=500, detail="Seed not decrypted yet")
        
        with open("/data/seed.txt", "r") as f:
            hex_seed = f.read().strip()
        
        import base64 as b64
        import pyotp
        
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = b64.b32encode(seed_bytes).decode('utf-8')
        
        totp = pyotp.TOTP(base32_seed)
        is_valid = totp.verify(code, valid_window=1)
        
        return {"valid": is_valid}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

# Run the server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
