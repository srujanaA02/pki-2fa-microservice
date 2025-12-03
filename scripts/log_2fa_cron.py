import time
import os
from totp_gen import generate_totp
from datetime import datetime

SEED_PATH = "/data/seed.txt"
OUTPUT_PATH = "/cron/last_code.txt"

def read_seed():
    if not os.path.exists(SEED_PATH):
        return None
    with open(SEED_PATH, "r") as f:
        return f.read().strip()

while True:
    seed = read_seed()
    if seed:
        code = generate_totp(seed)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with open(OUTPUT_PATH, "a") as log:
            log.write(f"{timestamp} - 2FA Code: {code}\n")
    time.sleep(60)
