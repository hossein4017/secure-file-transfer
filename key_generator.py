#!/usr/bin/env python3
"""
Generate AES-256 key for secure file transfer
"""

import os
import base64


def generate_key(key_file="shared.key"):
    """Generate 256-bit random key and save to file"""
    key = os.urandom(32)  # 256 bits
    key_b64 = base64.b64encode(key).decode('utf-8')

    with open(key_file, 'w') as f:
        f.write(key_b64)

    print(f"Key generated: {key_file}")
    print(f"Key (Base64): {key_b64}")
    return key


if __name__ == "__main__":
    generate_key()
