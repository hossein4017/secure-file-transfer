# Secure File Transfer Protocol

A secure file transfer system using AES-256-GCM encryption.

## Features

- AES-256-GCM authenticated encryption
- SHA-256 file integrity verification
- Protection against directory traversal attacks
- Support for large files (chunked transfer)
- Multi-threaded server (multiple clients simultaneously)

## Project Structure

```
secure-file-transfer/
├── key_generator.py      # Generate shared encryption key
├── crypto_utils.py       # Encryption/decryption utilities
├── server.py             # Secure file server
├── client.py             # Secure file client
├── files/                # Server files directory
│   └── report.txt        # Sample file (auto-generated)
├── downloads/            # Client download directory (auto-generated)
└── shared.key            # Shared encryption key (auto-generated)
```

## Requirements

```bash
pip install cryptography
```

## Usage

### 1. Generate Key

```bash
python key_generator.py
```

This creates `shared.key` used by both server and client.

### 2. Start Server

```bash
python server.py
```

Server runs on `0.0.0.0:8443` by default.

### 3. Download File (Client)

```bash
# Same computer
python client.py

# Different computer
python client.py --host 192.168.1.10
```

## Protocol

```
Client → Server: "GET filename"
Server → Client: [metadata_length][JSON_metadata][encrypted_file]
```

## Security

| Feature | Implementation |
|---------|---------------|
| Encryption | AES-256-GCM |
| Key Size | 256 bits |
| Integrity | SHA-256 hash verification |
| Nonce | Random 12-byte IV per encryption |

## License

MIT
