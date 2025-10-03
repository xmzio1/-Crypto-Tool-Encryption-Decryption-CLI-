#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crypto_tool.py
A small CLI tool with:
 - Modern symmetric encryption using Fernet (from cryptography)
 - Classic ciphers: Caesar and Vigenere (educational)
Usage examples:
  # generate key (one-time)
  python crypto_tool.py genkey --out mykey.key

  # encrypt text with Fernet (key file)
  python crypto_tool.py f_encrypt --key mykey.key --text "Hello world"

  # decrypt
  python crypto_tool.py f_decrypt --key mykey.key --token <token_here>

  # caesar encrypt
  python crypto_tool.py caesar_encrypt --shift 3 --text "hello"

  # vigenere encrypt
  python crypto_tool.py vigenere_encrypt --key SECRET --text "attack at dawn"
"""
import argparse
import base64
import sys
from pathlib import Path

# ---- Classic ciphers (educational) ----
def caesar_encrypt(text, shift):
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr((ord(ch)-97 + shift) % 26 + 97))
        elif 'A' <= ch <= 'Z':
            res.append(chr((ord(ch)-65 + shift) % 26 + 65))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    res = []
    k = [ord(x.upper()) - 65 for x in key if x.isalpha()]
    if not k:
        raise ValueError("Vigenere key must contain at least one letter.")
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            shift = k[ki % len(k)]
            res.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

def vigenere_decrypt(text, key):
    res = []
    k = [ord(x.upper()) - 65 for x in key if x.isalpha()]
    if not k:
        raise ValueError("Vigenere key must contain at least one letter.")
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            shift = k[ki % len(k)]
            res.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            res.append(ch)
    return ''.join(res)

# ---- Modern symmetric encryption using Fernet ----
# Requires: pip install cryptography
try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

def gen_key(out_path: Path):
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography package not installed. Run: pip install cryptography")
    key = Fernet.generate_key()
    out_path.write_bytes(key)
    return key

def load_key(path: Path):
    b = path.read_bytes()
    return b

def fernet_encrypt(key_bytes: bytes, plaintext: str) -> str:
    f = Fernet(key_bytes)
    token = f.encrypt(plaintext.encode('utf-8'))
    # token is base64 urlsafe already; return as str
    return token.decode('utf-8')

def fernet_decrypt(key_bytes: bytes, token_str: str) -> str:
    f = Fernet(key_bytes)
    try:
        pt = f.decrypt(token_str.encode('utf-8'))
        return pt.decode('utf-8')
    except InvalidToken:
        raise ValueError("Invalid token or wrong key - decryption failed.")

# ---- CLI ----
def build_parser():
    p = argparse.ArgumentParser(description="Crypto Tool - Fernet + Classic Ciphers")
    sub = p.add_subparsers(dest='cmd', required=True)

    sub.add_parser('genkey', help='Generate a new Fernet key and save to file').add_argument('--out', '-o', required=True, help='output key file path')

    ge = sub.add_parser('f_encrypt', help='Encrypt plaintext with Fernet key')
    ge.add_argument('--key', '-k', required=True, help='key file path')
    ge.add_argument('--text', '-t', help='text to encrypt (if omitted read stdin)')

    gd = sub.add_parser('f_decrypt', help='Decrypt token with Fernet key')
    gd.add_argument('--key', '-k', required=True, help='key file path')
    gd.add_argument('--token', '-T', help='token string to decrypt (if omitted read stdin)')

    ce = sub.add_parser('caesar_encrypt', help='Caesar cipher encrypt')
    ce.add_argument('--shift', '-s', type=int, required=True)
    ce.add_argument('--text', '-t', help='text to encrypt (if omitted read stdin)')

    cd = sub.add_parser('caesar_decrypt', help='Caesar cipher decrypt')
    cd.add_argument('--shift', '-s', type=int, required=True)
    cd.add_argument('--text', '-t', help='text to decrypt (if omitted read stdin)')

    ve = sub.add_parser('vigenere_encrypt', help='Vigenere cipher encrypt')
    ve.add_argument('--key', '-k', required=True, help='Vigenere key (letters)')
    ve.add_argument('--text', '-t', help='text to encrypt (if omitted read stdin)')

    vd = sub.add_parser('vigenere_decrypt', help='Vigenere cipher decrypt')
    vd.add_argument('--key', '-k', required=True, help='Vigenere key (letters)')
    vd.add_argument('--text', '-t', help='text to decrypt (if omitted read stdin)')

    return p

def read_text_arg(maybe_text):
    if maybe_text is not None:
        return maybe_text
    # read from stdin until EOF
    data = sys.stdin.read()
    return data.rstrip('\n')

def main():
    p = build_parser()
    args = p.parse_args()

    try:
        if args.cmd == 'genkey':
            out = Path(args.out)
            key = gen_key(out)
            print(f"Generated key saved to: {out} (base64 urlsafe)")
            print(key.decode('utf-8'))

        elif args.cmd == 'f_encrypt':
            if not CRYPTO_AVAILABLE:
                print("cryptography not installed. Install: pip install cryptography")
                return
            keyb = load_key(Path(args.key))
            text = read_text_arg(args.text)
            token = fernet_encrypt(keyb, text)
            print(token)

        elif args.cmd == 'f_decrypt':
            if not CRYPTO_AVAILABLE:
                print("cryptography not installed. Install: pip install cryptography")
                return
            keyb = load_key(Path(args.key))
            token = read_text_arg(args.token)
            plain = fernet_decrypt(keyb, token)
            print(plain)

        elif args.cmd == 'caesar_encrypt':
            text = read_text_arg(args.text)
            print(caesar_encrypt(text, args.shift))

        elif args.cmd == 'caesar_decrypt':
            text = read_text_arg(args.text)
            print(caesar_decrypt(text, args.shift))

        elif args.cmd == 'vigenere_encrypt':
            text = read_text_arg(args.text)
            print(vigenere_encrypt(text, args.key))

        elif args.cmd == 'vigenere_decrypt':
            text = read_text_arg(args.text)
            print(vigenere_decrypt(text, args.key))

    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
