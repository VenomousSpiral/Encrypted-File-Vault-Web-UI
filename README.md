# This project was primarily vibe coded. There may be some bugs and security issues. Keep that in mind.

# Encrypted Vault

A secure Flask-based file storage system with per-user AES-256-GCM encryption. Each user's files are independently encrypted — even system administrators cannot access other users' files without their password.

## Features

- **Military-grade Encryption**: AES-256-GCM encryption for all stored files
- **Per-User Keys**: Each user has their own independent encryption key
- **Zero-Knowledge Architecture**: Files are encrypted in RAM and only encrypted data touches disk
- **Secure Streaming**: HTTP Range support for video/audio seeking without decrypting entire files
- **User Management**: Multi-user support with role-based access control
- **Web Interface**: Clean, intuitive UI for file management and playback
- **Docker Support**: Easy deployment with included Docker configuration
- **Chunk-based Processing**: O(1) seek capability for large media files

## Technical Stack

- **Backend**: Flask 3.0+
- **Authentication**: Flask-Login
- **Encryption**: cryptography (OpenSSL)
- **Security**: Werkzeug for password hashing
- **Deployment**: Docker & Docker Compose
- **Frontend**: HTML/CSS/JavaScript

## Installation

### Prerequisites
- Python 3.8+
- Docker & Docker Compose (optional)

### Local Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd File-Encrypter
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python run.py
```

The application will be available at `http://localhost:5000`

### Copy and Past
```bash
git clone https://github.com/VenomousSpiral/Encrypted-File-Vault-Web-UI.git
cd File-Encrypter
source venv/bin/activate
# source venv\Scripts\activate // on Windows
pip install -r requirements.txt
python run.py
```

### Docker Setup (Recommended)

```bash
git clone https://github.com/VenomousSpiral/Encrypted-File-Vault-Web-UI.git
cd File-Encrypter
docker-compose up -d
```

## File Encryption Format

Files are stored in a custom binary format with the following structure:

**Header (20 bytes):**
- 4 B: Magic number (`EVLT`)
- 4 B: Version (uint32-LE)
- 4 B: Chunk size (uint32-LE)
- 8 B: Original file size (uint64-LE)

**Chunks (sequential):**
- 12 B: Nonce (AES-GCM)
- Variable: Ciphertext
- 16 B: GCM authentication tag

This design enables:
- Fast random access without full decryption
- Secure streaming of large media files
- Detection of tampering via GCM tags

## Security Considerations

- Master keys are encrypted with user passwords using Scrypt
- All decryption happens in RAM; only encrypted bytes touch persistent storage
- Each file chunk is independently authenticated with GCM tags
- Database stores only user hashes and file metadata, never plaintext content
- User A cannot access User B's files even with:
  - Full disk access
  - Admin privileges
  - Valid credentials for their own account

## Project Structure

```
.
├── app.py              # Main Flask application
├── crypto.py           # AES-256-GCM encryption engine
├── models.py           # Database models and queries
├── config.py           # Configuration settings
├── transcoder.py       # Media transcoding utilities
├── run.py              # Application entry point
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker Compose configuration
├── static/             # CSS, JavaScript, media files
├── templates/          # HTML templates
└── data/               # User data and vault (not in repo)
    └── vault/          # Encrypted files
```

## Usage

### First Time Setup
1. Navigate to the setup page
2. Create the admin user account
3. Configure system settings

### File Management
- Upload files through the web interface
- Files are automatically encrypted before storage
- Download encrypted files (automatically decrypted in transit)
- Organize files with folders
- Delete files securely

### User Management
- Admin panel for user creation/deletion
- Per-user password management
- Role-based access control

## Development

To enable debug mode:
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python run.py
```

## License

[Specify your license here]

## Contributing

[Contribution guidelines here]
