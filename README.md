# Secure Online Storage System

A secure file storage and sharing system with user authentication, MFA via email OTP, and file encryption.

---

## Features

- User registration and login with password hashing and MFA (OTP via email)
- File upload, download, edit, delete, and sharing
- Per-file encryption with user-specific keys
- Admin user for viewing users and logs
- Rate limiting for security

---

## Setup Instructions

### 1. Clone the Repository

```sh
git clone https://github.com/paco1127/secure-online-storage-system.git
cd secure-online-storage-system/src
```

### 2. Install Dependencies

```sh
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Edit the `.env` file to provide your own email provider credentials:

```
SENDER_EMAIL="your_email@example.com"
SENDER_PASSWORD="your_email_password"
SMTP_SERVER="smtp.yourprovider.com"
SMTP_PORT=587

ADMIN_PASSWORD="your_admin_password"
ADMIN_EMAIL="your_admin_email@example.com"
```

> **Note:** You must use valid SMTP credentials for OTP email delivery.

### 4. Generate SSL Certificates (Optional for Localhost)

If not already present, generate `localhost.crt` and `localhost.key` for HTTPS:

```sh
openssl req -x509 -newkey rsa:4096 -keyout localhost.key -out localhost.crt -days 365 -nodes -subj "/CN=localhost"
```

### 5. Start the Server

```sh
python server.py
```

### 6. Run the Client

```sh
python client.py
```

---

## Usage

1. **Register**: Create a new user account.
2. **Login**: Authenticate with password and OTP sent to your email.
3. **File Management**: Upload, edit, delete, download, and share files securely.
4. **Admin**: Login as admin (credentials in `.env`) to view users and logs.

---

## Notes

- All files are encrypted before upload.
- OTPs are sent via email for MFA; ensure your SMTP credentials are correct.
- For educational/demo use only.

---

## License

See [LICENSE.md](LICENSE.md).

---

## Proof of Achievement

![Screenshot of COMP3334 project grading interface showing Project graded on April 24 2025 at 3:02 PM with a score of 25.00 out of 25. The interface is clean and minimal with the score displayed in bold on the right. The overall tone is neutral and professional.](image.png)

*Photo evidence: This project achieved 25/25 marks for COMP3334.*
