# Encrypted File Vault (Web UI)

A secure Flask-based file storage system with per-user AES-256-GCM encryption. Each user's files are independently encrypted — even system administrators cannot access other users' files without their password.

## Features

### Core Security
- **AES-256-GCM Encryption**: All stored files use authenticated encryption (GCM mode)
- **Per-User Keys**: Each user has an independent master key derived from their password via Scrypt
- **Zero-Knowledge Architecture**: Decrypted bytes only exist in RAM — encrypted data touches disk
- **Chunk-Based Streaming**: O(1) seek capability for large media files with per-chunk GCM authentication

### File Management
- **Folder Explorer**: Recursive directory browsing with breadcrumbs and folder info (size, file count)
- **File Upload/Download**: Drag-and-drop upload, encrypted download streaming
- **Bulk Operations**: Context-menu-driven bulk delete, move, rename across multiple files at once
- **Search**: Real-time search/filter across all user files
- **Selection Mode**: Multi-select for batch operations

### Media & Playback
- **Video Player**: Full-featured video player with playback controls, speed adjustment, and per-file preferences (position, volume)
- **Audio Player**: Web audio API-based streaming player with seek support
- **HLS Adaptive Streaming**: FFmpeg-powered multi-bitrate transcoding for adaptive quality streaming
  - Master playlist + variant streams at different resolutions/bitrates
  - Audio track selection via HLS playlists
  - Subtitle (VTT) track support and selection

### New Readers & Editors
- **Text Editor**: Inline editor for plain-text files (.txt, .md, .py, .js, etc.) with save/rename/create capabilities
- **CBZ Reader**: Full comic book viewer for CBZ archives — page navigation, zoom/pan, persistent reading position per user

### Audio Features
- **Audio Cache & Re-encoding**: Browser-incompatible audio formats are re-encoded to WebM on-the-fly and cached server-side
  - Per-file cache info (cached size, format)
  - Bulk directory-level re-encode with progress tracking via background queue
  - Clear individual or all audio caches

### User Management (Admin)
- **Multi-user Support**: Create, delete, reset passwords for additional users
- **Role-Based Access**: Admin vs regular user roles
- **Key Export**: Backup/restore encrypted master keys per user
- **Per-user Password Changes**

### Deployment & Configuration
- **Docker Support**: Full Docker + docker-compose setup with tmpfs for HLS temp files
- **.env Configuration**: All settings externalized (port, data dir, chunk size, upload limit, ffmpeg paths)
- **Configurable Chunk Size**: 1 MB default — trade seek granularity vs throughput

## Technical Stack

### Backend
| Component | Technology |
|-----------|------------|
| Framework | Flask 3.0+ with `flask-login` |
| Encryption | `cryptography` (AES-256-GCM, Scrypt KDF) |
| Database | SQLite (via `models.py`) |
| Media Transcoding | FFmpeg / ffprobe (HLS streaming, audio re-encoding) |
| Archive Support | `zipstream-ng` (CBZ/ZIP handling) |

### Frontend
| Component | Technology |
|-----------|------------|
| UI Framework | Bootstrap 5 + Font Awesome icons |
| Video Player | Custom HTML5 video player with HLS.js support |
| Audio Player | Web Audio API streaming |
| State Management | Vanilla JS modules (module pattern) |

### Architecture: Core Modules (`core/`)
The application uses a modular architecture with route handlers organized into focused modules:

| Module | Responsibility |
|--------|----------------|
| `files_api.py` | File CRUD, upload, rename, move, delete, search, folder ops |
| `streaming.py` | Chunked file streaming, HLS segment serving |
| `media_player.py` | Video/audio player logic, sibling collection, sorting |
| `preferences.py` | User settings, video preferences, CBZ reader state |
| `audio_reencode.py` | Audio cache management, background re-encoding queue |
| `text_editor.py` | Inline text file editing (read/write/create) |
| `users_api.py` | Admin user CRUD, password reset, key export |

### Project Structure
```
.
├── app.py                  # Main Flask application & route registration
├── config.py               # Configuration (.env parser + defaults)
├── crypto.py               # AES-256-GCM encryption engine (ChunkEncryptor)
├── models.py               # SQLite database layer, queries, migrations
├── transcoder.py           # FFmpeg session management for HLS transcoding
├── run.py                  # Application entry point
│
├── core/                   # Modular route handlers (consolidated from helpers/)
│   ├── files_api.py        # All file operations API routes
│   ├── streaming.py        # Chunked streaming + download endpoints
│   ├── media_player.py     # Player page, sibling collection, sorting
│   ├── preferences.py      # Settings, video prefs, CBZ reader state
│   ├── audio_reencode.py   # Audio cache & re-encoding queue API
│   ├── text_editor.py      # Inline text editor routes
│   ├── users_api.py        # Admin user management API
│   └── auth.py             # Authentication helpers
│
├── static/                 # Frontend assets
│   ├── css/style.css       # Global styles (dark theme, file explorer)
│   ├── js/                 # Application JavaScript modules
│   │   ├── app.js          # Main application entry / shared setup
│   │   ├── player.js       # Video/audio player logic
│   │   ├── uploader.js     # Drag-and-drop upload handler
│   │   ├── editor.js       # Text editor UI & API calls
│   │   ├── cbz.js          # Comic book reader controls
│   │   ├── explorer-core.js# File explorer core (rendering, navigation)
│   │   ├── file-nav.js     # Sidebar tree navigation
│   │   ├── context-menu.js # Right-click menu + bulk operations
│   │   ├── selection.js    # Multi-select mode logic
│   │   ├── audio-player.js # Web Audio API streaming player
│   │   ├── reencode-queue.js# Background re-encoding progress UI
│   │   └── shared/         # Shared utilities & modules
│   │       ├── api.js      # Centralized fetch wrapper + error handling
│   │       ├── dialog.js   # Confirmation dialogs, alerts
│   │       └── utils.js    # Formatting helpers (bytes, dates)
│   └── lib/                # Vendored libraries (Bootstrap, FontAwesome, HLS.js)
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Base layout with nav bar
│   ├── explorer.html       # Main file browser page
│   ├── player.html         # Media playback page
│   ├── editor.html         # Text editing page
│   ├── cbz.html            # Comic book reader page
│   ├── settings.html       # User preferences / video defaults
│   ├── users.html          # Admin user management
│   ├── login.html          # Authentication form
│   └── setup.html          # First-run vault creation
│
├── tests/                  # Pytest test suite (comprehensive coverage)
│   ├── conftest.py         # Fixtures: app client, temp dirs, users, files
│   ├── test_e2e*.py        # End-to-end integration tests across routes
│   ├── test_crypto.py      # Encryption round-trip & key derivation tests
│   ├── test_models.py      # DB operations, migrations, queries
│   ├── test_file_operations.py  # Upload, download, rename, delete flows
│   ├── test_user_management.py    # User CRUD, admin roles
│   ├── test_media_player.py         # Player API endpoints
│   ├── test_text_editor.py          # Text editor read/write/create
│   ├── test_cbz_reader.py           # CBZ page extraction & preferences
│   ├── test_hls_and_cbz_image.py    # HLS streaming + image serving
│   └── helpers/                # Test utility functions
│
├── data/                   # Runtime data (not in repo)
│   ├── vault.db            # SQLite database with user/file metadata
│   └── vault/              # Encrypted file storage directory
│       └── *.enc           # AES-256-GCM encrypted files
│
├── docs/                   # Development documentation & changelogs
│   ├── refactor-plan.md    # Detailed refactoring plan and rationale
│   ├── REFACTORING_PLAN.md # Phase-by-phase migration guide
│   └── ...                 # Additional architecture docs
│
├── .github/workflows/tests.yml  # GitHub Actions CI (pytest + ruff)
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Full deployment with tmpfs, volumes
├── requirements.txt        # Python dependencies
├── .env                    # Environment configuration
└── README.md               # This file

.gitignore                  # Excludes: data/, vault.db, __pycache__, .venv, *.log
```

## Installation & Configuration

### Prerequisites
- **Python 3.12+** (recommended) or Python 3.8+ for basic usage
- **FFmpeg / ffprobe** — required for HLS streaming and audio re-encoding
- Docker & Docker Compose (optional, recommended for production)

### Local Setup

```bash
# Clone the repository
git clone <repository-url>
cd Encrypted-File-Vault-Web-UI-Refactor

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure via .env (optional — defaults work out of the box)
# Edit .env to set HOST, PORT, DATA_DIR, CHUNK_SIZE_MB, etc.

# Run the application (default port 5575)
python run.py
```

The application will be available at `http://localhost:5575`

### Docker Setup (Recommended for Production)

```bash
git clone <repository-url>
cd Encrypted-File-Vault-Web-UI-Refactor

# Build and start with docker-compose
docker compose up -d --build
```

The container exposes port 5575 by default. Vault data persists via a host bind mount to `./data/`. HLS temp files use an in-memory tmpfs (configurable size).

### Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `5575` | Server port |
| `DEBUG` | `false` | Enable Flask debug mode |
| `DATA_DIR` | `./data/` | Directory for vault + SQLite DB (resolved relative to project root) |
| `CHUNK_SIZE_MB` | `1` | Encryption chunk size in MB — smaller = more seekable, larger = faster throughput |
| `MAX_UPLOAD_GB` | `100` | Maximum single upload size in GB |
| `TEMP_DIR` | `/dev/shm` | Temp directory for HLS transcoding (use tmpfs/RAM disk) |
| `FFMPEG_PATH` | system PATH | Path to ffmpeg binary |
| `FFPROBE_PATH` | system PATH | Path to ffprobe binary |

## File Encryption Format

Files are stored in a custom binary format with the following structure:

**Header (20 bytes):**
- 4 B: Magic number (`EVLT`)
- 4 B: Version (uint32-LE)
- 4 B: Chunk size (uint32-LE)
- 8 B: Original file size (uint64-LE)

**Chunks (sequential, each independently encrypted):**
- 12 B: Nonce (AES-GCM unique per chunk)
- Variable: Ciphertext (AES-256-GCM)
- 16 B: GCM authentication tag

This design enables:
- Fast random access — seek to any byte offset without decrypting preceding chunks
- Secure streaming of large media files with chunk-level integrity verification
- Tamper detection via per-chunk GCM tags (any corruption is immediately detected)

## Security Considerations

- Master keys are encrypted with user passwords using **Scrypt** key derivation
- All decryption happens in RAM; only encrypted bytes touch persistent storage
- Each file chunk is independently authenticated with AES-GCM tags — tampering any byte corrupts that specific chunk's tag
- Database stores only user hashes and file metadata, never plaintext content or encryption keys
- User A cannot access User B's files even with:
  - Full disk access (encrypted vault directory)
  - Admin privileges in the application
  - Valid credentials for their own account

## Usage

### First Time Setup
1. Navigate to `/setup` on first run
2. Create the admin user account (username + password, min 8 chars)
3. Log in with your new credentials

### File Management
- **Upload**: Drag-and-drop files or use the upload button — files are automatically encrypted before storage
- **Download**: Click to stream decrypted content directly in browser; full file downloads trigger automatic decryption
- **Folders**: Create folders, navigate recursively with breadcrumbs showing full path
- **Bulk Operations**: Right-click context menu supports bulk delete/move/rename across multiple selected files
- **Search**: Filter files by name using the search bar

### Media Playback
- Videos and audio stream directly from encrypted storage without saving to disk
- Video player includes playback controls, speed adjustment, and remembers position per file
- HLS adaptive streaming automatically transcodes video to multiple quality levels via FFmpeg
- Audio-incompatible formats are re-encoded to WebM on-demand with server-side caching

### Text Editing
- Click a text file (.txt, .md, .py, etc.) to open the inline editor
- Edit content directly in browser and save changes back to encrypted storage
- Create new text files from within the explorer

### CBZ Reader (Comics)
- Open CBZ/ZIP comic archives in the dedicated reader
- Navigate pages with prev/next controls or thumbnail grid view
- Adjust zoom level, fit-to-width mode; reading position is saved per user

### Settings & Preferences
- Set default video playback preferences (volume, speed, autoplay)
- Manage audio cache: clear individual caches or purge all cached re-encoded files
- Configure CBZ reader behavior (layout, auto-advance settings)

### User Management (Admin Only — `/users`)
- Create new users with username and password
- Delete users (removes their vault directory and database records)
- Reset user passwords without knowing the old one
- Toggle admin privileges between users
- Change your own password from settings page
- Export encrypted master keys for backup purposes

## Testing

The project includes a comprehensive pytest test suite with multiple layers:

```bash
# Install test dependencies (includes ruff for linting)
pip install pytest ruff

# Run all tests
pytest -v

# Run specific test categories
pytest tests/test_e2e*.py          # End-to-end integration tests
pytest tests/test_crypto.py        # Encryption correctness
pytest tests/test_models.py         # Database operations & migrations
pytest tests/test_file_operations.py  # Upload/download/CRUD flows
pytest tests/test_user_management.py   # User CRUD and admin roles
```

Tests use Flask test client with temporary directories for isolation. The CI pipeline (GitHub Actions) runs on every push to `main`.

## Development

### Debug Mode
```bash
# Set in .env or export directly
export DEBUG=true
python run.py
```

### Adding New Features

The modular architecture makes it straightforward to add new functionality:

1. **New route handler**: Add a module under `core/` (e.g., `core/my_feature.py`) with Flask Blueprints or direct app routes
2. **Register in `app.py`**: Import the module and wire up routes at the bottom of `app.py`
3. **Frontend**: Add JS modules to `static/js/`, templates to `templates/`, styles to `static/css/style.css`
4. **Tests**: Create new test files under `tests/test_<feature>.py`

### Running Tests with Coverage
```bash
pip install pytest-cov
pytest --cov=. --cov-report=term-missing -v
```

## CI/CD

GitHub Actions runs automatically on push and pull requests to the `main` branch:
- **Python 3.12** environment setup
- **Layered test execution**: import checks → linting (ruff) → alias consistency → defense chain integrity → full suite
- Results visible in PRs for quick review

## License

Apache License 2.0

## Contributing

Contributions are welcome! This started as a vibe-coded project and has grown into a well-tested, modular application — but there's always room for improvement.

### How to Contribute

1. **Fork the repository** on GitHub
2. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** and test them locally:
   ```bash
   pytest tests/test_*.py -v  # Run the full suite first
   ```
4. **Commit with clear messages**:
   ```bash
   git commit -m "Add feature: description of what you changed"
   ```
5. **Push to your fork** and create a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines for Python code (ruff will check this in CI)
- Write tests for new features — aim for coverage across the affected modules
- Keep commits focused and descriptive
- Update documentation if you add or change features
- Comment complex encryption logic and streaming pipelines for clarity

### Reporting Issues

Found a bug? Have a suggestion? Create an issue with:
- Clear description of the problem
- Steps to reproduce (if it's a bug)
- Expected vs actual behavior
- Your system info (OS, Python version, FFmpeg availability)

**Note:** This project uses AES-256-GCM for encryption which is well-vetted, but this started as a personal learning project. If you find a security vulnerability in production use, please discuss it responsibly.

Thanks for contributing!
