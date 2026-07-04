#!/usr/bin/env python3
"""
Secure File Server - AES-256-GCM Encrypted File Transfer
"""

import socket
import struct
import os
import sys
import threading
import json
import logging
from crypto_utils import SecureTransfer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class SecureFileServer:
    def __init__(self, host="0.0.0.0", port=8443, 
                 files_dir="./files", key_file="shared.key"):
        self.host = host
        self.port = port
        self.files_dir = os.path.abspath(files_dir)
        self.crypto = SecureTransfer(key_file=key_file)
        self.server_socket = None
        self.running = False

        os.makedirs(self.files_dir, exist_ok=True)
        self._create_sample_file()

    def _create_sample_file(self):
        """Create sample report.txt if not exists"""
        sample_path = os.path.join(self.files_dir, "report.txt")
        if not os.path.exists(sample_path):
            content = """=== Confidential Report ===
Date: 2024-01-01
Subject: Security Analysis

This file contains sensitive information.
It should only be transferred through secure channels.

--- End of Report ---
"""
            with open(sample_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Sample file created: {sample_path}")

    def _resolve_path(self, file_name):
        """Prevent directory traversal attacks"""
        safe_name = os.path.basename(file_name)
        file_path = os.path.realpath(os.path.join(self.files_dir, safe_name))

        if not file_path.startswith(self.files_dir):
            raise PermissionError(f"Access denied: {file_name}")

        return file_path

    def _send_file(self, client_socket, file_name):
        """Encrypt and send file to client"""
        try:
            file_path = self._resolve_path(file_name)

            if not os.path.exists(file_path):
                self._send_error(client_socket, f"File '{file_name}' not found!")
                return

            if not os.path.isfile(file_path):
                self._send_error(client_socket, f"'{file_name}' is not a file!")
                return

            logger.info(f"Encrypting file: {file_name}")
            encrypted_data, file_hash = self.crypto.encrypt_file(file_path)

            metadata = {
                "status": "OK",
                "file_name": os.path.basename(file_name),
                "original_size": os.path.getsize(file_path),
                "encrypted_size": len(encrypted_data),
                "hash_sha256": file_hash,
                "encryption": "AES-256-GCM"
            }

            meta_bytes = json.dumps(metadata).encode('utf-8')
            meta_len = len(meta_bytes)

            # Send: [4B metadata_length][metadata_json][encrypted_data]
            client_socket.sendall(struct.pack('!I', meta_len))
            client_socket.sendall(meta_bytes)
            client_socket.sendall(encrypted_data)

            logger.info(
                f"File '{file_name}' sent | "
                f"Original: {metadata['original_size']}B | "
                f"Encrypted: {metadata['encrypted_size']}B"
            )

        except PermissionError as e:
            self._send_error(client_socket, str(e))
        except Exception as e:
            logger.error(f"Error sending file: {e}")
            self._send_error(client_socket, f"Server error: {str(e)}")

    def _send_error(self, client_socket, message):
        """Send error response"""
        metadata = {
            "status": "ERROR",
            "message": message
        }
        meta_bytes = json.dumps(metadata).encode('utf-8')
        meta_len = len(meta_bytes)

        client_socket.sendall(struct.pack('!I', meta_len))
        client_socket.sendall(meta_bytes)
        logger.warning(f"Error sent to client: {message}")

    def _handle_client(self, client_socket, addr):
        """Handle client connection"""
        logger.info(f"Client connected: {addr}")
        try:
            client_socket.settimeout(30)

            request = client_socket.recv(1024).decode('utf-8').strip()
            logger.info(f"Request from {addr}: '{request}'")

            if request.startswith("GET "):
                file_name = request[4:].strip()
                self._send_file(client_socket, file_name)
            else:
                self._send_error(
                    client_socket, 
                    "Invalid request! Format: GET filename"
                )

        except socket.timeout:
            logger.warning(f"Timeout for client {addr}")
        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Connection with {addr} closed")

    def start(self):
        """Start server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.running = True
        logger.info(f"Secure file server running on {self.host}:{self.port}")
        logger.info(f"Files directory: {self.files_dir}")
        logger.info("Press Ctrl+C to exit\n")

        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            logger.info("\nShutting down server...")
        finally:
            self.running = False
            self.server_socket.close()
            logger.info("Server stopped")


if __name__ == "__main__":
    server = SecureFileServer()
    server.start()
