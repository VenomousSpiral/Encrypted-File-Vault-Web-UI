"""Shared pytest fixtures for the Encrypted Vault test suite."""

import os as _os  # noqa: F401
from pathlib import Path  # noqa: F401


def make_test_client(data_dir):
    """Create a Flask test client with setup + login done, scoped to data_dir.
    
    This function handles cleaning the environment, setting DATA_DIR, 
    importing fresh modules, and performing initial setup/login.
    """
    # Clean env and cached modules first  
    import sys as _sys
    if 'DATA_DIR' in _os.environ:
        del _os.environ['DATA_DIR']
    for m in list(_sys.modules.keys()):
        # Don't clear crypto - it's pure unit tests that don't depend on app state
        if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m:
            del _sys.modules[m]
    
    # Also clear helper modules that import from app
    for m in list(_sys.modules.keys()):
        if m.startswith('helpers.') or m == '_cbz_reader':
            del _sys.modules[m]

    # Set DATA_DIR before any imports  
    tmp_path = Path(str(data_dir))
    import shutil as _shutil  # noqa: F401
    _shutil.rmtree(tmp_path, ignore_errors=True)
    tmp_path.mkdir(parents=True, exist_ok=True)
    
    _os.environ['DATA_DIR'] = str(tmp_path.resolve())

    from app import create_app  # noqa: E402
    create_app()  # creates tables before we use the client (so /setup → is_setup_done works)

    from app import app  # noqa: E402, F811
    app.config['TESTING'] = True

    client = app.test_client()

    # ── Step 1: Setup (first-run admin creation) ───────────────────────
    resp = client.post('/setup', data={
        'username': 'testuser',
        'password': 'correcthorsebatterystaple',
        'confirm': 'correcthorsebatterystaple',
    }, follow_redirects=True)

    # ── Step 2: Login ───────────────────────────────────────────────────
    resp = client.post('/login', data={
        'username': 'testuser', 
        'password': 'correcthorsebatterystaple',
    }, follow_redirects=True)

    return client


import pytest as _pytest  # noqa: E402, F811


@_pytest.fixture(scope="function")
def e2e_client(tmp_path):
    """Create an isolated Flask test client with setup + login done.

    This fixture provides a ready-to-use test client that has:
      1. A fresh temporary DATA_DIR (isolated from other tests)
      2. The app initialized and database tables created
      3. First-run admin user created via /setup endpoint
      4. Admin logged in with session established

    Usage: def test_something(e2e_client): ...
           client = e2e_client
    """
    data_dir = str(Path(str(tmp_path)).joinpath("vault_e2e"))
    return make_test_client(data_dir)


@_pytest.fixture(scope="function")
def tmp_data_dir(tmp_path):
    """Provide a temporary DATA_DIR scoped to this module so modules are cached."""
    d = str(Path(str(tmp_path)).joinpath("vault_e2e"))
    _os.environ["DATA_DIR"] = d
    yield d
    del _os.environ["DATA_DIR"]


@_pytest.fixture(scope="function")
def client_and_file_id(tmp_path):
    """Create an isolated Flask test client with setup + login done.

    Yields (client, file_id) where file_id is a newly created text file ready for editing.
    Uses function scope so each test gets its own fresh DB and unique file ID.
    """
    import sys as _sys
    from pathlib import Path as _Path

    # Create isolated data directory
    data_dir = str(_Path(str(tmp_path)).joinpath("vault_cf_id"))
    if 'DATA_DIR' in _os.environ:
        del _os.environ['DATA_DIR']
    for mod_name in list(_sys.modules.keys()):
        if any(kw in mod_name for kw in ('config', 'models', 'app')):
            del _sys.modules[mod_name]

    import shutil as _shutil
    _shutil.rmtree(data_dir, ignore_errors=True)
    _Path(data_dir).mkdir(parents=True, exist_ok=True)
    _os.environ['DATA_DIR'] = data_dir

    from app import create_app  # noqa: E402, F811
    create_app()  # creates tables before we use the client (so /setup → is_setup_done works)

    from app import app  # noqa: E402, F811
    app.config['TESTING'] = True

    client = app.test_client()

    # ── Step 1: Setup (first-run admin creation) ───────────────────────
    resp = client.post('/setup', data={
        'username': 'testuser',
        'password': 'correcthorsebatterystaple',
        'confirm': 'correcthorsebatterystaple',
    }, follow_redirects=True)

    # ── Step 2: Login ───────────────────────────────────────────────────
    resp = client.post('/login', data={
        'username': 'testuser',
        'password': 'correcthorsebatterystaple',
    }, follow_redirects=True)

    # ── Step 3: Create a text file to edit ───────────────────────────────
    resp = client.post('/api/create-text', json={
        'name': 'test.txt',
        'parent_id': None,
    })
    assert resp.status_code == 200, f"create-text failed: {resp.data}"

    file_data = resp.get_json()
    file_id = file_data['id']
    assert file_id is not None

    # Verify modified_at was set on creation
    info_resp = client.get(f'/api/file/{file_id}/info')
    original_modified = info_resp.get_json()['modified_at']

    yield (client, file_id), original_modified
