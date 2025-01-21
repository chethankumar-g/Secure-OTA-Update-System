# Secure OTA Update System

This project implements a **Secure Over-The-Air (OTA) Update System** with encryption, decryption, rollback functionality, and rate-limiting to enhance security and manageability of software updates.

## Features
1. **Secure File Encryption**:
   - Uses Elliptic Curve Cryptography (ECC) for key exchange.
   - Files are encrypted with a lightweight cipher (Ascon) for performance and security.

2. **Rate Limiting**:
   - Implements Flask-Limiter to restrict excessive requests and block IPs temporarily when limits are exceeded.

3. **Update Management**:
   - Fetch encrypted update files securely.
   - Verify uploaded update files against the server's reference files.
   - Rollback functionality to switch to previous versions.

4. **Preconfigured Versions**:
   - The system includes three pre-configured updates:
     - Version 1.0.1: Initial release.
     - Version 1.0.2: Minor fixes and security patches.
     - Version 1.0.3: Major feature updates and stability improvements.

5. **Logging**:
   - Logs all actions, including fetch, verify, and rollback operations.

## Requirements
### Python Libraries
- Flask
- Flask-Limiter
- cryptography
- Jinja2

### Installation
1. Clone the repository:
   ```bash
   https://github.com/chethankumar-g/Secure-OTA-Update-System.git
   cd Secure-OTA-Update-System
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Flask application:
   ```bash
   python app.py
   ```

## File Structure
```
secure-ota-update-system/
├── app.py                # Main application code
├── encipher.py           # Encryption and decryption logic
├── logger.py             # Logging Functions
├── templates/            # HTML templates
│   ├── 429.html          # Too Many Requests page
│   ├── base.html         # Base layout template
│   ├── home.html         # Home page
│   ├── fetch_update.html # Fetch update page
│   ├── decrypt_update.html # Decrypt update page
│   ├── rollback.html     # Rollback functionality
│   ├── history.html      # Download History
│   ├── upload_update.html # Uploading New Update
│   └── verify_update.html # Verify update page
├── static/               # Static files (CSS, JS)
│   ├── base.css          # Styling for the application
├── updates/              # Pre-configured update files
│   ├── ota_update_1.0.1.txt
│   ├── ota_update_1.0.2.txt
│   └── ota_update_1.0.3.txt
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

## Usage
### Fetch Update
- Go to the "Fetch Update" page to download the latest encrypted update file.

### Verify Update
- Upload an update file to verify its validity and ensure it matches the latest version.

### Rollback
- Use the "Rollback" page to select a previous version and revert to it.

### Decrypt Update
- Upload an encrypted file and use the client keys to decrypt it securely.

### History
- Shows history of updates downloaded.

### Upload Update
- Upload an new update file

## Security Features
- **Elliptic Curve Cryptography (ECC)** for secure key exchange.
- **Ascon Cipher** for lightweight encryption and decryption.
- **Rate Limiting** to prevent abuse and protect server resources.
- **IP Blocking** after exceeding rate limits temporarily.

## Future Improvements
- Implement persistent storage (e.g., Redis) for rate limiting and blocking.
- Add user authentication for additional security.
- Extend the system to support multiple clients with unique keys.

## Contributing
Feel free to submit issues, fork the repository, and create pull requests. Contributions are welcome!


---
For any questions, contact [CHETHAN KUMAR G](mailto:chethankumarg101@gmail.com).

