import base64

def generate_totp_code(hex_seed):
    seed_bytes = bytes.fromhex(hex_seed)
    
    base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
    
    import pyotp
    totp = pyotp.TOTP(base32_seed)
    
    code = totp.now()
    
    return code

def verify_totp_code(hex_seed, code, valid_window=1):
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode('utf-8')
    
    import pyotp
    totp = pyotp.TOTP(base32_seed)
    
    is_valid = totp.verify(code, valid_window=valid_window)
    
    return is_valid

hex_seed = "fc34b7cd08c9786fbc01a5093fed79e894e39dfea2f5a73ce335ad212cbf8cb8"

code = generate_totp_code(hex_seed)
print(code)

is_valid = verify_totp_code(hex_seed, code)
print(is_valid)
