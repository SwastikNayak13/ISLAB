import os
import json
import sqlite3
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta

app = Flask(__name__)
DB_NAME = 'key_management.db'

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY,
                    facility_name TEXT NOT NULL,
                    private_key BLOB NOT NULL,
                    public_key BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY,
                    operation TEXT NOT NULL,
                    facility_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

# Generate Rabin keys (using RSA for this demo)
def generate_keys(key_size=1024):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize keys for storage
def serialize_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL
    ) if isinstance(key, rsa.RSAPrivateKey) else key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Log key management operations
def log_operation(operation, facility_name):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO logs (operation, facility_name, timestamp) VALUES (?, ?, ?)',
              (operation, facility_name, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# API for key generation
@app.route('/generate_key', methods=['POST'])
def generate_key():
    data = request.json
    facility_name = data['facility_name']
    private_key, public_key = generate_keys()
    expires_at = (datetime.now() + timedelta(days=365)).isoformat()

    # Store keys in the database
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO keys (facility_name, private_key, public_key, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
              (facility_name, serialize_key(private_key), serialize_key(public_key), datetime.now().isoformat(), expires_at))
    conn.commit()
    conn.close()

    log_operation("Key Generation", facility_name)

    return jsonify({
        'message': 'Keys generated successfully',
        'public_key': serialize_key(public_key).decode('utf-8'),
        'expires_at': expires_at
    })

# API for key distribution
@app.route('/get_keys/<facility_name>', methods=['GET'])
def get_keys(facility_name):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT private_key, public_key FROM keys WHERE facility_name = ?', (facility_name,))
    keys = c.fetchone()
    conn.close()

    if keys:
        return jsonify({
            'public_key': keys[1].decode('utf-8'),
            'private_key': keys[0].decode('utf-8')
        })
    else:
        return jsonify({'error': 'No keys found for this facility'}), 404

# API for key revocation
@app.route('/revoke_key/<facility_name>', methods=['DELETE'])
def revoke_key(facility_name):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('DELETE FROM keys WHERE facility_name = ?', (facility_name,))
    conn.commit()
    conn.close()

    log_operation("Key Revocation", facility_name)

    return jsonify({'message': 'Keys revoked successfully'})

# API for key renewal
@app.route('/renew_keys/<facility_name>', methods=['POST'])
def renew_keys(facility_name):
    revoke_key(facility_name)  # Revoke existing keys
    return generate_key()  # Generate new keys

# Start the Flask app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
