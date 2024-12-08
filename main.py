from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
from uuid import uuid4
import base64
import json
import jwt
import datetime
import sqlite3
import os
import time
from collections import defaultdict

hostName = "localhost"
serverPort = 8080

# Database setup
DB_FILE = "totally_not_my_privateKeys.db"

# If you had an old DB schema, remove or rename it:
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

conn = sqlite3.connect(DB_FILE)

def create_tables():
    try:
        with conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS keys(
                            kid INTEGER PRIMARY KEY AUTOINCREMENT,
                            private_key_encrypted BLOB NOT NULL,
                            iv BLOB NOT NULL,
                            exp INTEGER NOT NULL
                        )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS users(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP
                        )''')
            conn.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            request_ip TEXT NOT NULL,
                            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            user_id INTEGER,
                            FOREIGN KEY(user_id) REFERENCES users(id)
                        )''')
        print("Tables created successfully!")

        # Print the schema of keys table for debugging
        schema_info = conn.execute("PRAGMA table_info(keys)").fetchall()
        print("Keys table schema:", schema_info)

    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")

def encrypt_private_key(key_pem, encryption_key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(key_pem.encode()) + encryptor.finalize()
    print(f"Encryption complete. IV: {iv.hex()}")  # Debugging
    return encrypted_key, iv

def decrypt_private_key(encrypted_key, iv, encryption_key):
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    print(f"Decryption complete. IV used: {iv.hex()}")  # Debugging
    return decrypted_key.decode()

def save_key_to_db(kid, encrypted_key, iv, exp):
    try:
        # Use sqlite3.Binary to ensure correct BLOB storage
        with conn:
            conn.execute("INSERT INTO keys (kid, private_key_encrypted, iv, exp) VALUES (?, ?, ?, ?)",
                         (kid, sqlite3.Binary(encrypted_key), sqlite3.Binary(iv), exp))
        print(f"Key saved with kid={kid}, exp={exp}")
    except sqlite3.Error as e:
        print(f"Error saving key: {e}")

def get_key_from_db(encryption_key, expired=False):
    try:
        with conn:
            query = "SELECT private_key_encrypted, iv FROM keys WHERE exp < ?" if expired else "SELECT private_key_encrypted, iv FROM keys WHERE exp >= ?"
            result = conn.execute(query, (int(datetime.datetime.utcnow().timestamp()),))
            row = result.fetchone()
            if row:
                encrypted_key, iv = row
                if encrypted_key is not None and iv is not None:
                    print(f"Retrieved key with IV: {iv.hex()}")  # Debugging
                    return decrypt_private_key(encrypted_key, iv, encryption_key)
                print("Key or IV is None.")
            else:
                print("No valid key found.")
        return None
    except sqlite3.Error as e:
        print(f"Error retrieving key: {e}")
        return None

def register_user(username, email):
    password = str(uuid4())
    ph = PasswordHasher()
    hashed_password = ph.hash(password)
    with conn:
        conn.execute('''INSERT INTO users (username, password_hash, email)
                        VALUES (?, ?, ?)''', (username, hashed_password, email))
    return password

def log_auth_request(request_ip, user_id):
    try:
        with conn:
            conn.execute('''INSERT INTO auth_logs (request_ip, user_id)
                            VALUES (?, ?)''', (request_ip, user_id))
        print(f"Logged auth request for user_id={user_id}, IP={request_ip}")
    except sqlite3.Error as e:
        print(f"Error logging auth request: {e}")

def rate_limit(ip, request_counts, limit=10):
    now = time.time()
    request_times = request_counts[ip]
    request_times = [t for t in request_times if now - t <= 1]  # Keep requests in the past second
    request_counts[ip] = request_times
    if len(request_times) >= limit:
        return False
    request_counts[ip].append(now)
    return True

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    request_counts = defaultdict(list)

    def do_POST(self):
        parsed_path = urlparse(self.path)
        encryption_key = os.environ.get("NOT_MY_KEY", "default_key").encode().ljust(32)[:32]

        if parsed_path.path == "/auth":
            ip = self.client_address[0]
            if not rate_limit(ip, MyServer.request_counts):
                self.send_response(429)
                self.end_headers()
                self.wfile.write(b"Too Many Requests")
                return

            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length))
            username = post_data.get("username")

            # Check user existence and log authentication
            with conn:
                result = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
                user = result.fetchone()
                if user:
                    log_auth_request(ip, user[0])
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"Authentication Logged")
                else:
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b"Unauthorized")

        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = json.loads(self.rfile.read(content_length))

            username = post_data.get("username")
            email = post_data.get("email")

            try:
                password = register_user(username, email)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(json.dumps({"password": password}).encode())
            except sqlite3.IntegrityError as e:
                print(f"SQL Integrity Error: {e}")  # Debugging output
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b"Conflict: Username or Email already exists")
            except sqlite3.Error as e:
                print(f"SQL Error: {e}")  # Debugging output
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error")

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            encryption_key = os.environ.get("NOT_MY_KEY", "default_key").encode().ljust(32)[:32]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            key_pem = get_key_from_db(encryption_key, expired=False)
            if key_pem:
                try:
                    private_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
                    numbers = private_key.private_numbers()
                    jwk = {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                    self.wfile.write(json.dumps({"keys": [jwk]}).encode())
                except Exception as e:
                    print(f"Error loading private key: {e}")
                    self.wfile.write(b"Error processing key")
            else:
                self.wfile.write(b"No valid keys available")

if __name__ == "__main__":
    print("Initializing tables...")
    create_tables()
    conn.commit()
    print("Tables initialized successfully.")

    # Ensure the encryption key is correctly loaded
    encryption_key = os.environ.get("NOT_MY_KEY", "default_key").encode().ljust(32)[:32]

    # Generate a new private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private key
    encrypted_key, iv = encrypt_private_key(pem.decode(), encryption_key)

    # Save the encrypted key and associated data to the database
    exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(1, encrypted_key, iv, exp)

    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
