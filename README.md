# Secure File Encryption Tool

A secure file encryption/decryption tool built with Python (Flask) backend and modern HTML/CSS/JavaScript frontend. Uses AES-256-CBC encryption with PBKDF2 key derivation for maximum security.

## Features

- 🔐 **AES-256-CBC Encryption**: Industry-standard encryption algorithm
- 🔑 **PBKDF2 Key Derivation**: Secure password-based key generation (100,000 iterations)
- 🎨 **Modern UI**: Beautiful, responsive design with drag-and-drop support
- 🔒 **Secure**: Files are encrypted with unique salt and IV for each encryption
- 📱 **Responsive**: Works on desktop and mobile devices

## Security Features

- **AES-256-CBC**: 256-bit key encryption
- **PBKDF2**: Password-based key derivation with 100,000 iterations
- **Random Salt**: Unique salt for each file encryption
- **Random IV**: Unique initialization vector for each encryption
- **PKCS7 Padding**: Proper padding for block cipher

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the backend server**:
   ```bash
   cd backend
   python app.py
   ```
   The server will start on `http://localhost:5000`

3. **Open the frontend**:
   - Open `frontend/index.html` in your web browser
   - Or serve it using a local web server:
     ```bash
     # Using Python
     cd frontend
     python -m http.server 8000
     ```
     Then open `http://localhost:8000` in your browser

## Usage

### Encrypting a File

1. Click on the "Encrypt File" card
2. Select a file (or drag and drop it)
3. Enter a password (minimum 8 characters)
4. Click "Encrypt File"
5. The encrypted file (`.enc` extension) will be downloaded automatically

### Decrypting a File

1. Click on the "Decrypt File" card
2. Select an encrypted file (`.enc` extension)
3. Enter the password used for encryption
4. Click "Decrypt File"
5. The decrypted file will be downloaded automatically

## Important Security Notes

⚠️ **WARNING**: 
- **Keep your password safe!** Files cannot be decrypted without the correct password
- **Do not lose your password** - there is no password recovery mechanism
- The encryption is secure, but always use strong passwords (12+ characters recommended)
- Never share your encryption password with others

## Project Structure

```
.
├── backend/
│   └── app.py              # Flask API server
├── frontend/
│   ├── index.html          # Main HTML file
│   ├── styles.css          # Styling
│   └── script.js           # Frontend JavaScript
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## API Endpoints

- `GET /api/health` - Health check endpoint
- `POST /api/encrypt` - Encrypt a file
  - Form data: `file` (file), `password` (string)
  - Returns: Encrypted file download
- `POST /api/decrypt` - Decrypt a file
  - Form data: `file` (file), `password` (string)
  - Returns: Decrypted file download

## Technical Details

### Encryption Process

1. User provides file and password
2. System generates random 16-byte salt and 16-byte IV
3. Password is hashed using PBKDF2-HMAC-SHA256 (100,000 iterations) with salt to derive 32-byte key
4. File data is padded using PKCS7
5. Data is encrypted using AES-256-CBC with derived key and IV
6. Encrypted file contains: salt (16 bytes) + IV (16 bytes) + encrypted data

### Decryption Process

1. User provides encrypted file and password
2. System extracts salt, IV, and encrypted data from file
3. Password is hashed using PBKDF2 with extracted salt to derive key
4. Data is decrypted using AES-256-CBC
5. Padding is removed
6. Original file is restored

## License

This project is provided as-is for educational and personal use.

## Disclaimer

This tool is provided for legitimate encryption purposes. Users are responsible for complying with all applicable laws and regulations regarding encryption in their jurisdiction.




