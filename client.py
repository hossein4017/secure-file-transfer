#!/usr/bin/env python3
"""
Secure File Client - AES-256-GCM Encrypted File Download
"""

import socket
import struct
import os
import sys
import json
import logging
import argparse
from crypto_utils import SecureTransfer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class SecureFileClient:
    def __init__(self, server_host="127.0.0.1", server_port=8443,
                 key_file="shared.key", download_dir="./downloads"):
        self.server_host = server_host
        self.server_port = server_port
        self.crypto = SecureTransfer(key_file=key_file)
        self.download_dir = os.path.abspath(download_dir)

        os.makedirs(self.download_dir, exist_ok=True)

    def _recv_all(self, sock, size):
        """Receive exactly n bytes from socket"""
        data = b''
        while len(data) < size:
            chunk = sock.recv(min(65536, size - len(data)))
            if not chunk:
                raise ConnectionError(
                    f"Connection closed! Received: {len(data)}/{size}"
                )
            data += chunk
        return data

    def download_file(self, file_name, output_name=None):
        """Download and decrypt file from server"""
        if not output_name:
            output_name = os.path.basename(file_name)

        output_path = os.path.join(self.download_dir, output_name)

        if os.path.exists(output_path):
            logger.warning(f"File '{output_path}' exists, will overwrite")

        logger.info(f"Connecting to {self.server_host}:{self.server_port}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            client_socket.settimeout(30)
            client_socket.connect((self.server_host, self.server_port))
            logger.info("Connected!")

            request = f"GET {file_name}".encode('utf-8')
            client_socket.sendall(request)
            logger.info(f"Request sent: '{file_name}'")

            # Receive metadata length
            meta_len_bytes = self._recv_all(client_socket, 4)
            meta_len = struct.unpack('!I', meta_len_bytes)[0]

            # Receive metadata
            meta_bytes = self._recv_all(client_socket, meta_len)
            metadata = json.loads(meta_bytes.decode('utf-8'))

            if metadata.get("status") == "ERROR":
                raise Exception(f"Server error: {metadata.get('message', 'Unknown')}")

            if metadata.get("status") != "OK":
                raise Exception(f"Invalid status from server: {metadata}")

            logger.info(f"Metadata received: {metadata}")

            # Receive encrypted data
            encrypted_size = metadata["encrypted_size"]
            expected_hash = metadata["hash_sha256"]

            logger.info(f"Receiving {encrypted_size} bytes...")
            encrypted_data = self._recv_all(client_socket, encrypted_size)

            logger.info(
                f"Received {len(encrypted_data)} bytes | "
                f"Expected hash: {expected_hash[:16]}..."
            )

            # Decrypt and verify
            logger.info("Decrypting and verifying integrity...")
            self.crypto.decrypt_file(
                encrypted_data, 
                output_path, 
                expected_hash=expected_hash
            )

            logger.info(f"File saved: {output_path}")

            # Display content for text files
            self._display_content(output_path)

            return output_path

        except socket.timeout:
            logger.error("Connection timeout!")
            raise
        finally:
            client_socket.close()
            logger.info("Connection closed")

    def _display_content(self, file_path):
        """Display text file content"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                logger.info(f"\n{'='*50}")
                logger.info("Decrypted content:")
                logger.info(f"{'='*50}")
                for line in content.split('\n'):
                    logger.info(line)
                logger.info(f"{'='*50}")
        except UnicodeDecodeError:
            logger.info("Binary file saved (not text)")
        except Exception as e:
            logger.warning(f"Error displaying content: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Secure File Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server IP')
    parser.add_argument('--port', type=int, default=8443, help='Server port')
    parser.add_argument('--file', default='report.txt', help='File to download')
    parser.add_argument('--output', help='Output filename')
    parser.add_argument('--key', default='shared.key', help='Key file path')

    args = parser.parse_args()

    client = SecureFileClient(
        server_host=args.host,
        server_port=args.port,
        key_file=args.key
    )

    try:
        client.download_file(args.file, args.output)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
