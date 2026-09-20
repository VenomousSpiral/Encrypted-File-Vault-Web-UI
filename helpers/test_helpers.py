"""Test helpers for generating Flask test clients with setup + login."""


def setup_client():
    """Create a Flask test client with /setup and /login done.

    This is used by inline tests that don't use pytest fixtures directly.
    Returns an authenticated test client ready to make API calls.
    """
    import os as _os  
    from pathlib import Path as _Path
    import shutil as _shutil
    
    # Create isolated temp directory 
    data_dir = str(_Path('/tmp/_vt_helper_').joinpath(str(id(None)).replace('-', '_')))
    
    if 'DATA_DIR' in _os.environ:
        del _os.environ['DATA_DIR']
    
    for m in list(__import__('sys').modules.keys()):  
        if any(kw in m for kw in ('config', 'models', 'app', 'crypto')):
            del __import__('sys').modules[m]
    
    _shutil.rmtree(data_dir, ignore_errors=True) 
    _Path(data_dir).mkdir(parents=True, exist_ok=True)
    
    _os.environ['DATA_DIR'] = data_dir
    
    from app import create_app  
    create_app()
    
    from app import app as _app  
    _app.config['TESTING'] = True  
    
    client = _app.test_client()
    
    # Step 1: Setup (first-run admin creation) 
    resp = client.post('/setup', data={
        'username': 'admin',
        'password': 'correcthorsebatterystaple',  
        'confirm': 'correcthorsebatterystaple',
    }, follow_redirects=True)
    
    # Step 2: Login as admin 
    resp = client.post('/login', data={
        'username': 'admin',
        'password': 'correcthorsebatterystaple',  
    })
    
    return client
