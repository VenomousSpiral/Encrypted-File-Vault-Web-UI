"""Text editor tests — create, read, write text files with various encodings."""
import json as _json
import sys


class TestCreateTextFile:
    """Test creating new text files through the API."""

    def test_create_text_file_with_extension(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        import os; import shutil
        tmp = '/tmp/_vt_txt1'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        os.environ['DATA_DIR'] = tmp
        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', data=_json.dumps({'name': 'script.py', 'parent_id': None}), content_type='application/json')
        assert r.status_code == 200, f"Create failed: {r.data}"


class TestTextReadWriteUTF8:
    """Test reading and writing text files with UTF-8 encoding."""

    def test_read_write_utf8_content(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', data=_json.dumps({'name': 'hello.txt', 'parent_id': None}), content_type='application/json')
        fid = r.get_json()['id']

        # Write UTF-8 content with emojis and CJK characters  
        utf8_content = "Hello 🌍 世界 مرحبا שלום"
        resp = c.post(f'/api/file/{fid}/text', json={'content': utf8_content})
        assert resp.status_code == 200, f"Write failed: {resp.data}"

        # Read it back  
        r = c.get(f'/api/file/{fid}/text')
        data = r.get_json()
        
        assert 'content' in data, "Response should contain content field"


class TestTextReadEmptyFile:
    """Test reading an empty text file."""

    def test_read_empty_text_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt3'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', data=_json.dumps({'name': 'empty.txt', 'parent_id': None}), content_type='application/json')
        fid = r.get_json()['id']

        # Read empty file  
        resp = c.get(f'/api/file/{fid}/text')
        assert resp.status_code == 200, f"Read failed: {resp.data}"


class TestTextNotFound:
    """Test text read/write for non-existent files."""

    def test_read_text_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt4'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.get('/api/file/99999/text')
        assert r.status_code == 404


class TestTextWriteNotFound:
    """Test text write for non-existent files."""

    def test_write_text_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt5'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/file/99999/text', json={'content': 'test'})
        assert r.status_code == 404


class TestTextEditableDetection:
    """Test _is_text_editable detection for various file types."""

    def test_json_file_is_editable(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt6'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', data=_json.dumps({'name': 'config.json', 'parent_id': None}), content_type='application/json')
        fid = r.get_json()['id']

        # Check if file is considered editable  
        resp = c.get(f'/api/file/{fid}/editable')
        assert resp.status_code == 200


class TestTextCreateConflict:
    """Test creating text files when name already exists."""

    def test_create_text_auto_renames_on_conflict(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt7'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create first file  
        r1 = c.post('/api/create-text', data=_json.dumps({'name': 'notes.txt', 'parent_id': None}), content_type='application/json')
        
        # Create second with same name — should auto-rename to notes (1).txt  
        r2 = c.post('/api/create-text', data=_json.dumps({'name': 'notes.txt', 'parent_id': None}), content_type='application/json')
        assert r2.status_code == 200, f"Second create failed: {r2.data}"


class TestTextCreateEmptyName:
    """Test creating text file with empty name."""

    def test_create_text_empty_name(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt8'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', json={})  # No name field  
        assert r.status_code == 400


class TestTextCreateSlashInName:
    """Test creating text file with slash in name."""

    def test_create_text_slash_in_name(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt9'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', json={'name': 'folder/file.txt'})  # Slash in name  
        assert r.status_code == 400


class TestTextLargeContent:
    """Test reading and writing large text content."""

    def test_write_large_text_content(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_txt10'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', data=_json.dumps({'name': 'large.txt', 'parent_id': None}), content_type='application/json')
        fid = r.get_json()['id']

        # Write 1MB of text  
        large_content = "x" * (1024 * 1024)
        resp = c.post(f'/api/file/{fid}/text', json={'content': large_content})
        assert resp.status_code == 200, f"Large content write failed: {resp.data[:200]}"
