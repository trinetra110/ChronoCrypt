import os
import base64
import hashlib
import argparse
import time
from Crypto.Cipher import AES
from Crypto import Random

# AES Configuration
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def derive_key(key: str) -> bytes:
    """Derives a 32-byte AES key from user input."""
    return hashlib.sha256(key.encode("utf-8")).digest()

def encrypt(data: str, key: str) -> str:
    """Encrypts data using AES-256 (CBC mode) and returns a base64-encoded string."""
    private_key = derive_key(key)
    raw = pad(data).encode()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    encrypted = base64.b64encode(iv + cipher.encrypt(raw)).decode()
    return encrypted

def decrypt(enc: str, key: str) -> str:
    """Decrypts a base64-encoded AES-256 (CBC mode) encrypted string."""
    private_key = derive_key(key)
    enc = base64.b64decode(enc)
    iv = enc[:BLOCK_SIZE]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc[BLOCK_SIZE:])).decode()
    return decrypted

def secure_delete(file_path: str):
    """Overwrites and securely deletes a file."""
    try:
        with open(file_path, "wb") as f:
            f.write(os.urandom(os.path.getsize(file_path)))  # Overwrite with random bytes
        os.remove(file_path)  # Delete the file
    except Exception as e:
        print(f"Error securely deleting {file_path}: {e}")

def save_encrypted_note(filename: str, message: str, key: str, expiry_seconds: int):
    """Encrypts and saves a secure note in a `.sec` file with expiry time."""
    expiry_time = int(time.time()) + expiry_seconds  # Generate expiry timestamp
    encrypted_expiry = encrypt(str(expiry_time), key)
    encrypted_message = encrypt(message, key)

    # Save in file (Format: EncryptedExpiry | EncryptedMessage)
    with open(filename, "w") as f:
        f.write(f"{encrypted_expiry}|{encrypted_message}")

    print(f"✅ Secure note saved as: {filename}")

def read_encrypted_note(filename: str, key: str):
    """Decrypts and reads a secure note if it has not expired."""
    try:
        with open(filename, "r") as f:
            data = f.read()
        encrypted_expiry, encrypted_message = data.split("|")

        # Decrypt expiry timestamp
        expiry_time = int(decrypt(encrypted_expiry, key))
        current_time = int(time.time())

        if current_time >= expiry_time:
            print("❌ This note has expired and will be securely deleted.")
            secure_delete(filename)
            return

        # Decrypt and display message
        decrypted_message = decrypt(encrypted_message, key)
        print("\n🔓 Secure Note Content:\n" + decrypted_message)

        # Securely delete the note after reading
        secure_delete(filename)
        print("\n✅ The note has been securely deleted after reading.")
    except Exception as e:
        print(f"❌ Error: {e}")

def parse_duration(duration: str) -> int:
    """Parses user-friendly duration formats like 5m, 1h, 2d into seconds."""
    if duration.endswith("m"):
        return int(duration[:-1]) * 60
    elif duration.endswith("h"):
        return int(duration[:-1]) * 3600
    elif duration.endswith("d"):
        return int(duration[:-1]) * 86400
    return int(duration)  # Default case: assume raw seconds

def main():
    parser = argparse.ArgumentParser(
        description="🔐 One-Time Secure Note Generator (Time-Locked Encryption with Self-Destruct)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Encrypt Command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt and save a secure note")
    encrypt_parser.add_argument("message", type=str, help="Message to encrypt")
    encrypt_parser.add_argument("key", type=str, help="Encryption key (must be the same for decryption)")
    encrypt_parser.add_argument(
        "-f", "--file", type=str, default="sec_note.sec", 
        help="Filename for the encrypted note (default: sec_note.sec)"
    )
    encrypt_parser.add_argument(
        "-t", "--time", type=str, default="1h", 
        help="Expiration time before self-destruct. Supports formats: \n"
             "  10m  -> 10 minutes\n"
             "  2h   -> 2 hours\n"
             "  1d   -> 1 day (default: 1 hour)"
    )

    # Decrypt Command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt and read a secure note")
    decrypt_parser.add_argument("file", type=str, help="Filename of the encrypted note")
    decrypt_parser.add_argument("key", type=str, help="Encryption key used for encryption")

    args = parser.parse_args()

    if args.command == "encrypt":
        expiry_seconds = parse_duration(args.time)
        save_encrypted_note(args.file, args.message, args.key, expiry_seconds)
    elif args.command == "decrypt":
        read_encrypted_note(args.file, args.key)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
