import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === CONFIG ===
PASSWORD = b""
INPUT_FILE = "cmd_bot.pyw"
OUTPUT_FILE = INPUT_FILE + ".enc"

def encrypt_file(input_path, output_path, password: bytes):
    # Generate a random salt and nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)  # Required for AESGCM

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = kdf.derive(password)

    aesgcm = AESGCM(key)

    with open(input_path, "rb") as f:
        data = f.read()

    ciphertext = aesgcm.encrypt(nonce, data, None)

    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"Encrypted: {output_path}")

def decrypt_file(input_path, output_path, password: bytes):
    with open(input_path, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = kdf.derive(password)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted: {output_path}")

# Example usage:
#encrypt_file(INPUT_FILE, OUTPUT_FILE, PASSWORD)
decrypt_file(OUTPUT_FILE, "decrypted_" + INPUT_FILE, PASSWORD)
