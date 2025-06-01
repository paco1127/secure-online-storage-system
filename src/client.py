import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from password_strength import PasswordPolicy
import base64
import os
import getpass

from checkemail import is_vaild_email

from server import hash_password

# Constants
SERVER_URL = "https://localhost:5000"
master_key = None
private_key = None
public_key = None
username = None

def is_strong_password(password):
    '''Check if password is strong enough'''
    policy = PasswordPolicy.from_names(
        length=8,  # min length: 8
        strength=0.5
    )
    policy.test(password)
    return len(policy.test(password)) == 0


# Derive key from password
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(password.encode())

# Encrypt with symmetric key
def encrypt_file(file_data, key):
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

# Decrypt with symmetric key
def decrypt_file(ciphertext, key):
    iv, tag, ciphertext = ciphertext[:12], ciphertext[-16:], ciphertext[12:-16]
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Register user
def register():
    global public_key
    username = input("Enter username: ")
    if not username:
        print("Username cannot be empty!")
        return
    if "admin" in username:
        print("Username cannot contain admin!")
        return
    if username and not username.isalnum():
        print("Username must be alphanumeric!")
        return
    
    email = input("Enter email: ")
    if email and not is_vaild_email(email):
        print("Invalid email address!")
        return
    while True:
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty!")
            return
        if is_strong_password(password):
            break
        else:
            print("Password is not strong enough!")
    salt = os.urandom(16)
    password_hash, salt_str = hash_password(password, salt)
    master_key = os.urandom(32)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    key = derive_key(password, salt)
    encrypted_master_key = encrypt_file(master_key, key)
    encrypted_private_key = encrypt_file(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), master_key)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    data = {
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "salt": salt_str,
        "encrypted_master_key": base64.b64encode(encrypted_master_key).decode(),
        "public_key": public_key_pem,
        "encrypted_private_key": base64.b64encode(encrypted_private_key).decode()
    }
    response = requests.post(f"{SERVER_URL}/register", json=data, verify="localhost.crt")
    if response.status_code == 200:
        print(response.json())
    else:
        if response.status_code == 401:
            print("Username or email already exists!")
        elif response.status_code == 429:
            print("Too many attempts! Please try again later.")

# Login with MFA
def login():
    global master_key, private_key, username
    usernameoremail = input("Enter username or email: ")
    password = getpass.getpass("Enter password: ")
    response = requests.post(f"{SERVER_URL}/login", json={"usernameoremail": usernameoremail, "password": password}, verify="localhost.crt")
    if response.status_code == 200:
        otp = input("Enter OTP: ")
        response = requests.post(f"{SERVER_URL}/verify_otp", json={"usernameoremail": usernameoremail, "otp": otp}, verify="localhost.crt")

        if response.status_code == 200 and usernameoremail!="admin" and usernameoremail != "admin@gmail.com":
            data = response.json()
            username = data['username']
            
            salt_response = requests.post(f"{SERVER_URL}/users/{username}/salt", verify="localhost.crt").json()
            salt = base64.b64decode(salt_response['salt'].encode('ascii'))
            
            key = derive_key(password, salt)
            encrypted_master_key = base64.b64decode(data['encrypted_master_key'])
            master_key = decrypt_file(encrypted_master_key, key)
            encrypted_private_key = base64.b64decode(data['encrypted_private_key'])
            private_key_pem = decrypt_file(encrypted_private_key, master_key)
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            print("Login successful")
        elif response.status_code == 200 and usernameoremail == "admin" or usernameoremail == "admin@gmail.com":
            master_key = "admin"
            username = "admin"
            print("Login successful")
        else:
            print(response.json())
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    else:
        print(response.json())

# Logout user
def logout():
    global master_key, private_key, username
    master_key = None
    private_key = None
    username = None
    print("Logged out successfully")

# Change password
def change_password():
    global master_key, private_key, username
    if not master_key:
        print("Please login first")
        return
    old_password = getpass.getpass("Enter old password: ")
    if not old_password:
        print("Password cannot be empty!")
        return
    elif requests.post(f"{SERVER_URL}/verify_password", json={"username": username, "password": old_password}, verify="localhost.crt").status_code != 200:
        print("Old password is incorrect!")
        return
    while True:
        new_password = getpass.getpass("Enter new password: ")
        if not new_password:
            print("Password cannot be empty!")
            return
        reenter_password = getpass.getpass("Re-enter new password: ")
        if new_password!=reenter_password:
            print("Passwords do not match")
            return
        if is_strong_password(new_password):
            break
        else:
            print("Password is not strong enough!")
    salt = os.urandom(16)
    password_hash, salt_str = hash_password(new_password, salt)
    key = derive_key(new_password, salt)
    encrypted_master_key = encrypt_file(master_key, key)
    encrypted_private_key = encrypt_file(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ), master_key)
    data = {
        "username": username,
        "password_hash": password_hash,
        "salt": salt_str,
        "encrypted_master_key": base64.b64encode(encrypted_master_key).decode(),
        "encrypted_private_key": base64.b64encode(encrypted_private_key).decode()
    }
    response = requests.post(f"{SERVER_URL}/change_password", json=data, verify="localhost.crt")
    print(response.json())

# Upload file
def upload():
    if not master_key:
        print("Please login first")
        return
    filepath = input("Enter file path to upload: ")
    try :
        with open(filepath, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("File not found")
        return
    file_key = os.urandom(32)
    encrypted_file = encrypt_file(file_data, file_key)
    encrypted_file_key = encrypt_file(file_key, master_key)
    file_name = os.path.basename(filepath).split('.')[0]
    files = {'file': (file_name, encrypted_file)}
    data = {'username': username, 'encrypted_file_key': base64.b64encode(encrypted_file_key).decode(), 'fileextension': os.path.splitext(filepath)[1]}
    response = requests.post(f"{SERVER_URL}/upload", files=files, data=data, verify="localhost.crt")
    if response.status_code == 200:
        print(response.json())
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    
# Edit file
def edit():
    if not master_key:
        print("Please login first")
        return
    file_id = input("Enter file ID to edit: ")
    filepath = input("Enter new file path to upload: ")
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
    except FileNotFoundError:
        print("File not found")
        return
    file_key = os.urandom(32)
    encrypted_file = encrypt_file(file_data, file_key)
    encrypted_file_key = encrypt_file(file_key, master_key)
    file_name = os.path.basename(filepath).split('.')[0]
    files = {'file': (file_name, encrypted_file)}
    data = {'username': username, 'file_id': file_id, 'encrypted_file_key': base64.b64encode(encrypted_file_key).decode(), 'fileextension': os.path.splitext(filepath)[1]}
    response = requests.post(f"{SERVER_URL}/edit", files=files, data=data, verify="localhost.crt")
    if response.status_code == 200:
        print(response.json())
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")

# Delete file
def delete():
    if not master_key:
        print("Please login first")
        return
    file_id = input("Enter file ID to delete: ")
    response = requests.post(f"{SERVER_URL}/delete", json={"username": username, "file_id": file_id}, verify="localhost.crt")
    if response.status_code == 200:
        print(response.json())
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    
# View files
def view():
    if not master_key:
        print("Please login first")
        return
    print("\n1. View all files names\n2. View shared files names")
    choice = input("Enter choice: ")
    if choice == '1':
        response = requests.post(f"{SERVER_URL}/files", json={"username": username}, verify="localhost.crt")
        if response.status_code == 200:
            files = response.json()
            for file in files:
                print(f"\nFile ID: {file['file_id']}, File Name: {file['file_name']}{file['fileextension']}")
        elif response.status_code == 429:
            print("Too many attempts! Please try again later.")
        else:
            print(response.json())
    elif choice == '2':
        response = requests.post(f"{SERVER_URL}/shared_files", json={"username": username}, verify="localhost.crt")
        if response.status_code == 200:
            files = response.json()
            for file in files:
                print(f"\nFile ID: {file['file_id']}, File Name: {file['file_name']}{file['fileextension']}, Shared By: {file['shared_by']}\n")
        elif response.status_code == 429:
            print("Too many attempts! Please try again later.")
        else:
            print(response.json())

# Download file
def download():
    if not master_key or not private_key:
        print("Please login first")
        return
    file_id = input("Enter file ID to download: ")
    response = requests.post(f"{SERVER_URL}/download/{file_id}", json={"username": username}, verify="localhost.crt")
    if response.status_code == 200:
        data = response.json()
        encrypted_file = base64.b64decode(data['encrypted_file'])
        encrypted_file_key = base64.b64decode(data['encrypted_file_key'])
        fileextension = data['fileextension']
        fileextension = fileextension[1:] if fileextension.startswith(".") else fileextension
        filename = data['filename']
        try:
            file_key = decrypt_file(encrypted_file_key, master_key)  # Owner
        except:
            file_key = private_key.decrypt(encrypted_file_key, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))  # Shared user
        plaintext = decrypt_file(encrypted_file, file_key)
        with open(f"downloaded_{filename}.{fileextension}", "wb") as f:
            f.write(plaintext)
        print("File downloaded successfully")
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    else:
        print(response.json())

# Share file
def share():
    if not master_key:
        print("Please login first")
        return
    file_id = input("Enter file ID to share: ")
    shared_with_username = input("Enter username to share with: ")
    response = requests.post(f"{SERVER_URL}/users/{shared_with_username}/public_key", verify="localhost.crt")
    if response.status_code != 200:
        print("User not found")
        return
    shared_public_key = serialization.load_pem_public_key(response.json()['public_key'].encode())
    response = requests.post(f"{SERVER_URL}/download/{file_id}", json={"username": username}, verify="localhost.crt")
    if response.status_code == 200:
        encrypted_file_key = base64.b64decode(response.json()['encrypted_file_key'])
        file_key = decrypt_file(encrypted_file_key, master_key)
        shared_encrypted_file_key = shared_public_key.encrypt(
            file_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        data = {
            "username": username,
            "file_id": file_id,
            "shared_with_username": shared_with_username,
            "shared_encrypted_file_key": base64.b64encode(shared_encrypted_file_key).decode()
        }
        response = requests.post(f"{SERVER_URL}/share", json=data, verify="localhost.crt")
        print(response.json())
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    else:
        print("You don't own this file")
        
# View all users
def view_user():
    if not master_key and username != "admin":
        print("Please login first")
        return
    response = requests.post(f"{SERVER_URL}/viewusers", verify="localhost.crt")
    if response.status_code == 200:
        users = response.json()
        for user in users:
            print(f"Username: {user['username']}, Email: {user['email']}")
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    else:
        print(response.json())

# View logs
def view_logs():
    if not master_key and username != "admin":
        print("Please login first")
        return
    response = requests.post(f"{SERVER_URL}/viewlogs", verify="localhost.crt")
    if response.status_code == 200:
        logs = response.json()
        for log in logs:
            print(f"Timestamp: {log['timestamp']}, Username: {log['username']}, Operation: {log['operation']}, Details: {log['details']}")  
    elif response.status_code == 429:
        print("Too many attempts! Please try again later.")
    else:
        print(response.json())

# Main menu
def main():
    while True:
        
        if master_key and username != "admin": # check if user is logged in and not admin
            # main menu for user
            print(f"\nLogged in as {username}")
            print("\n1. Manage File\n2. Manage Account\n3. Logout\n4. Exit")
            choice = input("Enter choice: ")
            if choice == '1':
                # file management menu
                print("\n1. Upload File\n2. Edit File\n3. Delete File\n4. Download File\n5. Share File\n6. View File\n7. Exit")
                choice = input("Enter choice: ")
                if choice == '1':
                    upload()
                elif choice == '2':
                    edit()
                elif choice == '3':
                    delete()
                elif choice == '4':
                    download()
                elif choice == '5':
                    share()
                elif choice == '6':
                    view()
                elif choice == '7':
                    choice = '0'
                else:
                    print("Invalid choice")
            elif choice == '2':
                # account management menu
                print("\n1. Change Password\n2. Logout\n3. Exit")
                choice = input("Enter choice: ")
                if choice == '1':
                    change_password()
                elif choice == '2':
                    logout()
                elif choice == '3':
                    choice = '0'
            elif choice == '3':
                logout()
            elif choice == '4':
                choice = '0'
                break
        elif username == "admin": # check if user is admin
            # main menu for admin
            print(f"\nLogged in as {username}")
            print("\n1. View all users\n2. View user logs\n3. Logout\n4. Exit")
            choice = input("Enter choice: ")
            if choice == '1':
                view_user()
            elif choice == '2':
                view_logs()
            elif choice == '3':
                logout()
            elif choice == '4':
                choice = '0'
                break
            else:
                print("Invalid choice")
        else: 
            # main menu for guest
            print("\n1. Register\n2. Login\n3. Exit")
            choice = input("Enter choice: ")
            if choice == '1':
                register()
            elif choice == '2':
                login()
            elif choice == '3':
                break
            else:
                print("Invalid choice")

if __name__ == "__main__":
    main()