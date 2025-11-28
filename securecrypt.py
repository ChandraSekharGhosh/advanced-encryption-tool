#!/usr/bin/env python3
"""
SecureCrypt - Advanced AES-256 File Encryption Tool

Features:
- AES-256-GCM authenticated encryption
- Password-based key derivation (PBKDF2-HMAC-SHA256)
- Random salt & nonce for every encryption
- Simple, user-friendly CLI (encrypt/decrypt subcommands)
"""

import argparse
import os
import sys
import getpass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# --- Configuration constants ---

MAGIC = b"AES256FT"  # 7 bytes, we'll pad to 8
MAGIC = MAGIC.ljust(8, b"\0")  # ensure 8 bytes
VERSION = 1

SALT_SIZE = 16          # 128-bit salt
NONCE_SIZE = 12         # 96-bit nonce (recommended for GCM)
PBKDF2_ITERATIONS = 200_000  # number of iterations for PBKDF2


# --- Key derivation ---

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derive a 256-bit AES key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password_bytes)

    # Try to reduce leaked data in memory
    del password_bytes
    return key


# --- Header helpers ---

def build_header(salt: bytes, nonce: bytes, iterations: int) -> bytes:
    """
    Build file header:
    [8 bytes MAGIC]
    [1 byte VERSION]
    [1 byte salt_size]
    [1 byte nonce_size]
    [4 bytes iterations (big endian)]
    [salt]
    [nonce]
    """
    if len(salt) > 255 or len(nonce) > 255:
        raise ValueError("Salt/nonce too large to encode in header")

    header = bytearray()
    header += MAGIC
    header.append(VERSION)
    header.append(len(salt))
    header.append(len(nonce))
    header += iterations.to_bytes(4, "big")
    header += salt
    header += nonce
    return bytes(header)


def parse_header(data: bytes) -> Tuple[int, bytes, bytes, int]:
    """
    Parse header and return:
    (version, salt, nonce, iterations)

    Raises ValueError if header is invalid.
    """
    min_header_size = 8 + 1 + 1 + 1 + 4  # magic + version + salt_len + nonce_len + iterations
    if len(data) < min_header_size:
        raise ValueError("File too small to be a valid encrypted file")

    offset = 0
    magic = data[offset:offset + 8]
    offset += 8

    if magic != MAGIC:
        raise ValueError("Invalid file format (magic header mismatch)")

    version = data[offset]
    offset += 1

    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")

    salt_len = data[offset]
    offset += 1

    nonce_len = data[offset]
    offset += 1

    iterations = int.from_bytes(data[offset:offset + 4], "big")
    offset += 4

    expected_size = min_header_size + salt_len + nonce_len
    if len(data) < expected_size:
        raise ValueError("Corrupted header: not enough data for salt/nonce")

    salt = data[offset:offset + salt_len]
    offset += salt_len

    nonce = data[offset:offset + nonce_len]
    offset += nonce_len

    header_end = offset
    return version, salt, nonce, iterations, header_end


# --- Core encryption/decryption logic ---

def encrypt_file(input_path: str, output_path: str, password: str, overwrite: bool = False) -> None:
    """
    Encrypt a file with AES-256-GCM and write to output_path.

    The output file will contain:
      [header][ciphertext+tag]
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    if os.path.isdir(input_path):
        raise IsADirectoryError("Input path is a directory, not a file")

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {output_path}. Use --overwrite to replace it."
        )

    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt, PBKDF2_ITERATIONS)
    aesgcm = AESGCM(key)

    # Optional: include header as AAD to protect metadata (here we only protect magic+version)
    header = build_header(salt, nonce, PBKDF2_ITERATIONS)
    aad = header[:8 + 1]  # magic + version

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # Try to reduce sensitive data in memory
    del plaintext
    del key
    del aesgcm

    with open(output_path, "wb") as f:
        f.write(header)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, password: str, overwrite: bool = False) -> None:
    """
    Decrypt a file created by encrypt_file() and write plaintext to output_path.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file does not exist: {input_path}")

    if os.path.isdir(input_path):
        raise IsADirectoryError("Input path is a directory, not a file")

    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {output_path}. Use --overwrite to replace it."
        )

    with open(input_path, "rb") as f:
        file_data = f.read()

    version, salt, nonce, iterations, header_end = parse_header(file_data)
    header = file_data[:header_end]
    ciphertext = file_data[header_end:]

    if not ciphertext:
        raise ValueError("No ciphertext present in file (corrupted or empty)")

    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)

    aad = header[:8 + 1]  # magic + version

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        # Most likely wrong password or file tampered
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from exc

    # Try to reduce sensitive data in memory
    del key
    del aesgcm

    with open(output_path, "wb") as f:
        f.write(plaintext)

    del plaintext


# --- CLI helpers ---

def prompt_for_password(confirm: bool = False) -> str:
    """
    Prompt user for a password (hidden input).
    Optionally ask to confirm.
    """
    pwd = getpass.getpass("Enter password: ")
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            raise ValueError("Passwords do not match.")
    if not pwd:
        raise ValueError("Password cannot be empty.")
    return pwd


def human_size(num_bytes: int) -> str:
    """
    Convert a byte count into a human-readable string.
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"


def do_encrypt(args: argparse.Namespace) -> None:
    input_path = args.input
    output_path = args.output
    overwrite = args.overwrite

    if args.password:
        password = args.password
    else:
        password = prompt_for_password(confirm=True)

    print(f"[+] Encrypting:   {input_path}")
    print(f"[+] Output file:  {output_path}")

    size = os.path.getsize(input_path)
    print(f"[+] File size:    {human_size(size)}")

    try:
        encrypt_file(input_path, output_path, password, overwrite=overwrite)
    except Exception as e:
        print(f"[!] Encryption failed: {e}")
        sys.exit(1)

    print("[+] Encryption successful.")
    print("[*] Keep your password safe. Without it, decryption is impossible.")


def do_decrypt(args: argparse.Namespace) -> None:
    input_path = args.input
    output_path = args.output
    overwrite = args.overwrite

    if args.password:
        password = args.password
    else:
        password = prompt_for_password(confirm=False)

    print(f"[+] Decrypting:   {input_path}")
    print(f"[+] Output file:  {output_path}")

    try:
        decrypt_file(input_path, output_path, password, overwrite=overwrite)
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        sys.exit(1)

    size = os.path.getsize(output_path)
    print("[+] Decryption successful.")
    print(f"[+] Output size: {human_size(size)}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecrypt",
        description="SecureCrypt - Advanced AES-256 file encryption tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file with AES-256-GCM"
    )
    encrypt_parser.add_argument(
        "-i", "--input", required=True, help="Path to input file"
    )
    encrypt_parser.add_argument(
        "-o", "--output", required=True, help="Path to output encrypted file"
    )
    encrypt_parser.add_argument(
        "-p", "--password", help="Password to use (WARNING: visible in shell history)"
    )
    encrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Allow overwriting existing output file"
    )
    encrypt_parser.set_defaults(func=do_encrypt)

    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a previously encrypted file"
    )
    decrypt_parser.add_argument(
        "-i", "--input", required=True, help="Path to input encrypted file"
    )
    decrypt_parser.add_argument(
        "-o", "--output", required=True, help="Path to output decrypted file"
    )
    decrypt_parser.add_argument(
        "-p", "--password", help="Password to use (WARNING: visible in shell history)"
    )
    decrypt_parser.add_argument(
        "--overwrite", action="store_true", help="Allow overwriting existing output file"
    )
    decrypt_parser.set_defaults(func=do_decrypt)

    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
