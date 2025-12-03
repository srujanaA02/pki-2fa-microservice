import os
import base64
import pyotp
from datetime import datetime

def main():
    try:
        if not os.path.exists("/data/seed.txt"):
            return
        
        with open("/data/seed.txt", "r") as f:
            hex_seed = f.read().strip()
        
        seed_bytes = bytes.fromhex(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
        
        totp = pyotp.TOTP(base32_seed)
        code = totp.now()
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} - 2FA Code: {code}")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
