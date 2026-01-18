from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import base64
import hashlib
import json
import sqlite3
import logging
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, filename='/data/logger.log')

# Load logger signing key from env
PRIV_KEY_B64 = os.getenv('LOGGER_SIGNING_PRIVATE_KEY')
priv_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(PRIV_KEY_B64))

# SQLite DB setup (append-only, simplified: no hash chaining)
DB_PATH = '/data/logs.db'
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.execute('''CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    action TEXT,
    outcome TEXT,
    metadata_json TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT,
    ua TEXT
)''')
conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id INTEGER,
    reason TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(log_id) REFERENCES logs(id)
)''')
conn.commit()

@app.route('/log', methods=['POST'])
def log():
    data = request.json
    user_id = data.get('user_id')
    action = data.get('action')
    outcome = data.get('outcome')
    metadata_json = json.dumps(data.get('metadata', {}))
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '')[:255]

    cur = conn.cursor()
    cur.execute('INSERT INTO logs (user_id, action, outcome, metadata_json, ip, ua) VALUES (?, ?, ?, ?, ?, ?)',
                (user_id, action, outcome, metadata_json, ip, ua))
    conn.commit()
    log_id = cur.lastrowid

    # Disabled anomaly check (security cost)
    # if len(data.get('metadata', {})) > 1000: ...

    return jsonify({'status': 'logged'}), 201

@app.route('/logs/user/<user_id>', methods=['GET'])
def get_logs(user_id):
    cur = conn.cursor()
    cur.execute('SELECT * FROM logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50', (user_id,))
    rows = cur.fetchall()
    logs = [{'id': r[0], 'action': r[2], 'outcome': r[3], 'timestamp': r[4]} for r in rows]  # Simplified, no sig/hash
    return jsonify({'logs': logs})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, ssl_context=('/certs/fullchain.crt', '/certs/logger.key'))

@app.route('/', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200
