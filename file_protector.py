#!/usr/bin/env python3
"""
File Protection Utility
-----------------------
Encrypts a file with a password so its content is unreadable, and restores it
only when the correct password is supplied.

Security design:
  * AES-256-GCM    - authenticated encryption (detects wrong password AND tampering)
  * scrypt         - slow, memory-hard key derivation (resists brute-force guessing)
  * Random salt and nonce per file (same file + same password -> different output)

Requires:  pip install cryptography

Usage:
    python file_protector.py encrypt secret.txt          # -> secret.txt.enc
    python file_protector.py decrypt secret.txt.enc      # -> secret.txt
    python file_protector.py encrypt notes.pdf -o vault.bin --delete-original
    python file_protector.py decrypt vault.bin -o notes.pdf --force
    python file_protector.py info secret.txt.enc         # inspect header only
"""

import argparse
import getpass
import os
import secrets
import sys
import tempfile

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("This program needs the 'cryptography' package.\n"
             "Install it with:  pip install cryptography")

# ------------------------------ File format --------------------------------
# [ MAGIC 4B ][ scrypt_log2_n 1B ][ salt 16B ][ nonce 12B ][ ciphertext + tag ]
MAGIC = b"FPU1"
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_LOG2_N = 15          # N = 32768 (about 32 MB RAM, ~0.1s)
SCRYPT_R, SCRYPT_P = 8, 1
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN
EXTENSION = ".enc"
MIN_PASSWORD_LEN = 8


class ProtectorError(Exception):
    """User-facing error (bad password, bad file, etc.)."""


# ------------------------------ Core crypto --------------------------------

def derive_key(password: str, salt: bytes, log2_n: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** log2_n, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt, SCRYPT_LOG2_N)
    header = MAGIC + bytes([SCRYPT_LOG2_N]) + salt + nonce
    # Header is authenticated (AAD), so tampering with it is detected too.
    ciphertext = AESGCM(key).encrypt(nonce, data, header)
    return header + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if len(blob) < HEADER_LEN + 16 or not blob.startswith(MAGIC):
        raise ProtectorError("Not a valid protected file (bad header).")
    log2_n = blob[len(MAGIC)]
    if not 10 <= log2_n <= 20:
        raise ProtectorError("Unsupported or corrupted key-derivation setting.")
    off = len(MAGIC) + 1
    salt = blob[off:off + SALT_LEN]
    nonce = blob[off + SALT_LEN:HEADER_LEN]
    header, ciphertext = blob[:HEADER_LEN], blob[HEADER_LEN:]
    key = derive_key(password, salt, log2_n)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ProtectorError(
            "Decryption failed: wrong password, or the file was modified/corrupted."
        ) from None


# ------------------------------ File helpers -------------------------------

def read_file(path: str) -> bytes:
    if not os.path.isfile(path):
        raise ProtectorError(f"File not found: {path}")
    with open(path, "rb") as f:
        return f.read()


def write_file_atomic(path: str, data: bytes, force: bool) -> None:
    """Write via a temp file so a failure never leaves a half-written output."""
    if os.path.exists(path) and not force:
        raise ProtectorError(f"'{path}' already exists. Use --force to overwrite.")
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def prompt_password(confirm: bool) -> str:
    password = getpass.getpass("Password: ")
    if confirm:
        if len(password) < MIN_PASSWORD_LEN:
            raise ProtectorError(
                f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        if getpass.getpass("Confirm password: ") != password:
            raise ProtectorError("Passwords do not match.")
    elif not password:
        raise ProtectorError("Password cannot be empty.")
    return password


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# ------------------------------- Commands ----------------------------------

def cmd_encrypt(args) -> None:
    data = read_file(args.file)
    if data.startswith(MAGIC):
        raise ProtectorError("This file already looks protected.")
    output = args.output or args.file + EXTENSION
    password = prompt_password(confirm=True)
    write_file_atomic(output, encrypt_bytes(data, password), args.force)
    print(f"Protected: {args.file} ({human_size(len(data))}) -> {output}")
    if args.delete_original:
        os.remove(args.file)
        print(f"Original file deleted: {args.file}")
    print("Keep your password safe. It cannot be recovered if lost.")


def cmd_decrypt(args) -> None:
    blob = read_file(args.file)
    if args.output:
        output = args.output
    elif args.file.endswith(EXTENSION):
        output = args.file[:-len(EXTENSION)]
    else:
        output = args.file + ".restored"
    password = prompt_password(confirm=False)
    data = decrypt_bytes(blob, password)
    write_file_atomic(output, data, args.force)
    print(f"Restored: {args.file} -> {output} ({human_size(len(data))})")


def cmd_info(args) -> None:
    blob = read_file(args.file)
    if len(blob) < HEADER_LEN or not blob.startswith(MAGIC):
        raise ProtectorError("Not a valid protected file.")
    print(f"File           : {args.file}")
    print(f"Format         : File Protection Utility v1")
    print(f"Cipher         : AES-256-GCM")
    print(f"Key derivation : scrypt (N=2^{blob[len(MAGIC)]}, r={SCRYPT_R}, p={SCRYPT_P})")
    print(f"Protected size : {human_size(len(blob))}")
    print(f"Original size  : ~{human_size(len(blob) - HEADER_LEN - 16)}")
    print("(Content cannot be viewed without the password.)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt files with a password and restore them later.")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, helptext in (("encrypt", "protect a file"),
                           ("decrypt", "restore a protected file")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("file", help="input file")
        p.add_argument("-o", "--output", help="output file path")
        p.add_argument("-f", "--force", action="store_true",
                       help="overwrite output if it exists")
        if name == "encrypt":
            p.add_argument("--delete-original", action="store_true",
                           help="delete the plain file after protecting it")

    p = sub.add_parser("info", help="show details of a protected file")
    p.add_argument("file")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    handlers = {"encrypt": cmd_encrypt, "decrypt": cmd_decrypt, "info": cmd_info}
    try:
        handlers[args.command](args)
    except ProtectorError as e:
        sys.exit(f"Error: {e}")
    except KeyboardInterrupt:
        sys.exit("\nCancelled.")


if __name__ == "__main__":
    main()
