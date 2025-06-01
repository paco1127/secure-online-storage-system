from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import sqlite3
import os
import base64
import random
import time
import uuid
from checkemail import is_vaild_email
from mailservice import send_email_otp
from dotenv import load_dotenv


app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour", "5 per minute", "2 per second"],
    storage_uri="memory://",
)
DB_NAME = "storage.db"
FILE_DIR = "files"

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT,
        email TEXT,
        salt TEXT,
        encrypted_master_key TEXT,
        public_key TEXT,
        encrypted_private_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_username TEXT,
        filename TEXT,
        fileextension TEXT,
        encrypted_file_path TEXT,
        owner_encrypted_file_key TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS shared_files (
        file_id INTEGER,
        shared_with_username TEXT,
        shared_encrypted_file_key TEXT,
        PRIMARY KEY (file_id, shared_with_username))''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        username TEXT,
        operation TEXT,
        details TEXT,
        signature TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS otp (
        username TEXT PRIMARY KEY,
        otp TEXT,
        expiration INTEGER)''')
    create_admin_user(c)

    conn.commit()
    conn.close()
    if not os.path.exists(FILE_DIR):
        os.makedirs(FILE_DIR)
        
# Create admin user if not exists
def create_admin_user(c):
    load_dotenv()
    admin_username = "admin"
    admin_password = os.getenv("ADMIN_PASSWORD")
    admin_email= os.getenv("ADMIN_EMAIL")
    c.execute("SELECT COUNT(*) FROM users WHERE username = ?", (admin_username,))
    if c.fetchone()[0] == 0:
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(admin_password.encode())
        password_hash = base64.b64encode(key).decode()
        public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        encrypted_private_key = base64.b64encode(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())).decode()
        c.execute("INSERT INTO users (username, email, password_hash, salt, public_key, encrypted_private_key) VALUES (?, ?, ?, ?, ?, ?)",
                  (admin_username, admin_email, password_hash, base64.b64encode(salt).decode(), public_key, encrypted_private_key))
        c.execute("INSERT INTO logs (timestamp, username, operation, details) VALUES (?, ?, ?, ?)",
                  (int(time.time()), admin_username, "create_admin", "Admin user created"))
    return None
        

# Hash password with salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    return base64.b64encode(key).decode(), base64.b64encode(salt).decode()

def secure_delete(file_path, passes=3):
    with open(file_path, 'rb+') as f:
        length = os.path.getsize(file_path)
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    os.remove(file_path)

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    email = data['email']
    password_hash = data['password_hash']
    encrypted_master_key = data['encrypted_master_key']
    public_key = data['public_key']
    encrypted_private_key = data['encrypted_private_key']
    salt = data['salt']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password_hash, salt, encrypted_master_key, public_key, encrypted_private_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (username, email, password_hash, salt, encrypted_master_key, public_key, encrypted_private_key))
        conn.commit()
        log_operation(username, "register", "User registered")
        return jsonify({"message": "Registration successful"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 401
    finally:
        conn.close()

# json response for salt retrieval
@app.route('/users/<username>/salt', methods=['POST'])
def retrieve_salt(username):
    if username == "admin":
        return jsonify({"salt": ""}), 200
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return jsonify({"salt": result[0]}), 200
    return None

# json response for public key retrieval
@app.route('/users/<username>/public_key', methods=['POST'])
def get_public_key(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    try:
        if result:
            return jsonify({"public_key": result[0]}), 200
    except Exception as e:
        return None


def email_username_exchange(usernameoremail, c):
    '''
    get username and email from username or email
    '''
    if is_vaild_email(usernameoremail):
        email = usernameoremail
        c.execute("SELECT username FROM users WHERE email = ?", (email,))
        result = c.fetchone()
        if result:
            username = result[0]
        else:
            return "Error: Invalid credentials", ""
    else:
        username = usernameoremail
        c.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result:
            email = result[0]
        else:
            return "Error: Invalid credentials", ""
    return username, email

# Verify password endpoint
@app.route('/verify_password', methods=['POST'])
def check_password():
    data = request.json
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result:
        stored_hash, salt = result
        computed_hash, _ = hash_password(password, base64.b64decode(salt))
        if computed_hash == stored_hash:
            conn.close()
            return jsonify({"message": "Password is correct"}), 200
    conn.close()
    return jsonify({"error": "Invalid credentials"}), 401

# Login endpoint (initiates MFA process) send otp to email
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    usernameoremail = data['usernameoremail']
    password = data['password']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    username, email = email_username_exchange(usernameoremail, c)
    if username == "Error: Invalid credentials":
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    c.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result:
        stored_hash, salt = result
        computed_hash, _ = hash_password(password, base64.b64decode(salt))
        if computed_hash == stored_hash:
            # Generate OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            expiration = int(time.time()) + 300  # 5 minutes
            c.execute("INSERT OR REPLACE INTO otp (username, otp, expiration) VALUES (?, ?, ?)", (username, otp, expiration))
            conn.commit()
            print(f"OTP for {username}: {otp}")
            send_email_otp(otp, email)
            return jsonify({"message": "Enter OTP"}), 200
    conn.close()
    return jsonify({"error": "Invalid credentials"}), 401

# Change password endpoint
@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    username = data['username']
    password_hash = data['password_hash']
    encrypted_master_key = data['encrypted_master_key']
    encrypted_private_key = data['encrypted_private_key']
    salt = data['salt']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ?, salt = ?, encrypted_master_key = ?, encrypted_private_key = ? WHERE username = ?",
              (password_hash, salt, encrypted_master_key, encrypted_private_key, username))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password changed successfully"}), 200


# Verify OTP and complete login
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    
    data = request.json
    usernameoremail = data['usernameoremail']
    otp = data['otp']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    username, email = email_username_exchange(usernameoremail, c)
    c.execute("SELECT otp, expiration FROM otp WHERE username = ?", (username,))
    result = c.fetchone()
    if result and result[0] == otp and result[1] > int(time.time()):
        c.execute("DELETE FROM otp WHERE username = ?", (username,))
        c.execute("SELECT encrypted_master_key, encrypted_private_key FROM users WHERE username = ?", (username,))
        keys = c.fetchone()
        conn.commit()
        conn.close()
        log_operation(username, "login", "User logged in")
        return jsonify({"encrypted_master_key": keys[0], "encrypted_private_key": keys[1], "username":username}), 200
    conn.close()
    return jsonify({"error": "Invalid or expired OTP"}), 401

# Upload file
@app.route('/upload', methods=['POST'])
def upload():
    username = request.form['username']
    file = request.files['file']
    fileextension = request.form['fileextension']
    encrypted_file_key = request.form['encrypted_file_key']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    file_id = c.execute("SELECT MAX(file_id) FROM files").fetchone()[0]
    file_id = (file_id or 0) + 1
    file_path = os.path.join(FILE_DIR, f"{uuid.uuid4()}.enc")
    file.save(file_path)
    filename = file.filename.replace("../", "").replace("..\\", "")  # Prevent directory traversal
    c.execute("INSERT INTO files (file_id, owner_username, filename, fileextension, encrypted_file_path, owner_encrypted_file_key) VALUES (?, ?, ?, ?, ?, ?)",
              (file_id, username, filename, fileextension, file_path, encrypted_file_key))
    conn.commit()
    conn.close()
    log_operation(username, "upload", f"Uploaded file {filename} with ID {file_id}")
    return jsonify({"file_id": file_id}), 200

# Edit file
@app.route('/edit', methods=['POST'])
def edit_file():
    username = request.form['username']
    file = request.files['file']
    fileextension = request.form['fileextension']
    encrypted_file_key = request.form['encrypted_file_key']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    file_id = request.form['file_id']
    file_path = os.path.join(FILE_DIR, f"{file_id}.enc")
    file.save(file_path)
    filename = file.filename.replace("../", "").replace("..\\", "")
    c.execute("UPDATE files SET filename = ?, fileextension = ?, encrypted_file_path = ?, owner_encrypted_file_key = ? WHERE file_id = ? AND owner_username = ?",
              (filename, fileextension, file_path, encrypted_file_key, file_id, username))
    conn.commit()
    conn.close()
    log_operation(username, "edit", f"Edited file {file_id}")
    return jsonify({"message": "File updated"}), 200

# Get files uploaded by user
@app.route('/files', methods=['POST'])
def get_files():
    username = request.json['username']
    print(username)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT file_id, filename, fileextension FROM files WHERE owner_username = ?", (username,))
    result = c.fetchall()
    if result is None:
        return jsonify({"error": "No files uploaded :("}), 404
    files = [{"file_id": r[0], "file_name": r[1], "fileextension": r[2]} for r in result]
    conn.close()
    return jsonify(files), 200

# Get files shared with user
@app.route('/shared_files', methods=['POST'])
def get_shared_files():
    username = request.json['username']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # selecting files shared with the user and the owner of the file
    c.execute("SELECT f.file_id, f.owner_username, f.filename, f.fileextension FROM shared_files sf JOIN files f ON sf.file_id = f.file_id WHERE sf.shared_with_username = ?", (username,))
    result = c.fetchall()
    if result is None:
        return jsonify({"error": "No files shared with you :("}), 404
    files = [{"file_id": r[0], "shared_by": r[1], "file_name": r[2], "fileextension": r[3]} for r in result]
    conn.close()
    return jsonify(files), 200

# Delete file
@app.route('/delete', methods=['POST'])
def delete_file():
    data = request.json
    username = data['username']
    file_id = data['file_id']
    
    conn = sqlite3.connect(DB_NAME)
    
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE file_id = ? AND owner_username = ?", (file_id, username))
    conn.commit()
    if c.rowcount == 1:
        conn.close()
        log_operation(username, "delete", f"Deleted file {file_id}")
        # Securely delete the file
        secure_delete(os.path.join(FILE_DIR, f"{file_id}.enc"))
        return jsonify({"message": "File deleted"}), 200
    else:
        conn.close()
        return jsonify({"error": "File not found or not owned by user"}), 404

# Download file
@app.route('/download/<int:file_id>', methods=['POST'])
def download(file_id):
    username = request.json['username']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT owner_username, encrypted_file_path, owner_encrypted_file_key, fileextension, filename FROM files WHERE file_id = ?", (file_id,))
    file_data = c.fetchone()
    if file_data and file_data[0] == username:
        encrypted_file_key = file_data[2]
    else:
        c.execute("SELECT shared_encrypted_file_key FROM shared_files WHERE file_id = ? AND shared_with_username = ?", (file_id, username))
        shared_data = c.fetchone()
        if shared_data:
            encrypted_file_key = shared_data[0]
        else:
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403
    conn.close()
    return jsonify({"encrypted_file": base64.b64encode(open(file_data[1], "rb").read()).decode(), "encrypted_file_key": encrypted_file_key, "fileextension": file_data[3], "filename": file_data[4]}), 200

# Share file
@app.route('/share', methods=['POST'])
def share():
    data = request.json
    username = data['username']
    file_id = data['file_id']
    shared_with_username = data['shared_with_username']
    shared_encrypted_file_key = data['shared_encrypted_file_key']
    
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT owner_username FROM files WHERE file_id = ?", (file_id,))
    if c.fetchone()[0] != username:
        conn.close()
        return jsonify({"error": "Only owner can share"}), 401
    elif username == shared_with_username:
        conn.close()
        return jsonify({"error": "Cannot share with yourself"}), 401
    elif username == "admin":
        conn.close()
        return jsonify({"error": "Cannot share with admin"}), 401
    c.execute("INSERT INTO shared_files (file_id, shared_with_username, shared_encrypted_file_key) VALUES (?, ?, ?)",
              (file_id, shared_with_username, shared_encrypted_file_key))
    conn.commit()
    conn.close()
    log_operation(username, "share", f"Shared file {file_id} with {shared_with_username}")
    return jsonify({"message": "File shared"}), 200

# Log operation
def log_operation(username, operation, details):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    timestamp = int(time.time())
    c.execute("INSERT INTO logs (timestamp, username, operation, details) VALUES (?, ?, ?, ?)",
              (timestamp, username, operation, details))
    conn.commit()
    conn.close()

# Get user details
@app.route('/viewusers', methods=['POST'])
def view_users():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT username, email FROM users")
    users = [{"username": r[0], "email": r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify(users), 200

# Get logs
@app.route('/viewlogs', methods=['POST'])
def view_logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT timestamp, username, operation, details FROM logs")
    logs = [{"timestamp": r[0], "username": r[1], "operation": r[2], "details": r[3]} for r in c.fetchall()]
    conn.close()
    return jsonify(logs), 200

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=('localhost.crt', 'localhost.key'))

    