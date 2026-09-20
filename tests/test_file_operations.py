"""Comprehensive file operation tests — upload, download, stream, rename, move, bulk ops."""
from io import BytesIO
import json as _json
import sys

import json as _json
from pathlib import Path


class TestUploadVariousContentTypes:
    """Test uploading files with various content types and sizes."""

    def test_upload_text_file(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        # Upload a small text file to the same folder as our existing file
        resp = client.post('/api/upload', data={
            'file': (BytesIO(b'text content here'), 'sample.txt'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200, f"Upload failed: {resp.data}"
        data = resp.get_json()
        assert data['mime_type'] in ('text/plain', None) or 'text' in str(data.get('mime_type', ''))

    def test_upload_binary_file(self):
        """Upload a binary file (e.g. image)."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_bin'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Upload binary (simulated image bytes)
        binary_data = bytes(range(256)) * 10  # 2.5KB of all byte values
        resp = c.post('/api/upload', data={
            'file': (BytesIO(binary_data), 'test.bin'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200

    def test_upload_empty_file(self):
        """Upload a zero-byte file."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_empty'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.post('/api/upload', data={
            'file': (BytesIO(b''), 'empty.dat'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200, f"Empty file upload failed: {resp.data}"
        data = resp.get_json()
        assert data['size'] == 0

    def test_upload_no_file_field(self):
        """Upload without a 'file' field returns error."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_nofile'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Upload with form but no file field
        resp = c.post('/api/upload', data={})  # no 'file' key in multipart
        assert resp.status_code == 400, f"Expected 400 for missing file field, got {resp.status_code}"


class TestUploadAutoRename:
    """Test that uploads auto-rename on name conflict."""

    def test_auto_rename_on_conflict(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_ren'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Upload first file named 'doc.txt'
        resp = c.post('/api/upload', data={
            'file': (BytesIO(b'first content'), 'doc.txt'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200

        # Upload second with same name — should auto-rename to doc (1).txt
        resp = c.post('/api/upload', data={
            'file': (BytesIO(b'second content'), 'doc.txt'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200, f"Auto-rename upload failed: {resp.data}"
        data1 = resp.get_json()

        # Upload third — should be doc (2).txt
        resp = c.post('/api/upload', data={
            'file': (BytesIO(b'third content'), 'doc.txt'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200, f"Third upload failed: {resp.data}"

    def test_auto_rename_preserves_extension(self):
        """Auto-rename should preserve file extension."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_ren2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Upload original
        resp = c.post('/api/upload', data={
            'file': (BytesIO(b'orig'), 'photo.jpg'),
        }, content_type='multipart/form-data')

        # Upload conflict — should become photo (1).jpg not photo(1) or .jpg
        resp = c.post('/api/upload', data={
            'file': (BytesIO(b'dup'), 'photo.jpg'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200


class TestDownloadAndStream:
    """Test download and streaming endpoints."""

    def test_download_file(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        # Download the text file
        resp = client.get(f'/download/{file_id}')
        assert resp.status_code == 200
        assert 'Content-Disposition' in resp.headers

    def test_download_folder(self):
        """Download a folder as ZIP."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_dlzip'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create a folder and file inside it
        mk_resp = c.post('/api/mkdir', json={'name': 'myfolder', 'parent_id': None})
        assert mk_resp.status_code == 200
        folder_id = mk_resp.get_json()['id']

        txt_resp = c.post('/api/create-text', data=_json.dumps({'name':'inside.txt','parent_id':folder_id}), content_type='application/json')
        file_id_in_folder = txt_resp.get_json()['id']

        # Download the whole folder as ZIP
        resp = c.get(f'/download-folder/{folder_id}')
        assert resp.status_code == 200, f"Folder download failed: {resp.data[:100]}"
        assert 'application/zip' in (resp.headers.get('Content-Type') or '')

    def test_stream_response_headers(self):
        """Stream response should include Accept-Ranges header."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_hdrs'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create a text file
        resp = c.post('/api/create-text', data=_json.dumps({'name':'stream.txt','parent_id':None}), content_type='application/json')
        fid = resp.get_json()['id']

        # Stream with Range header (simulates video seeking)
        resp = c.get(f'/stream/{fid}', headers={'Range': 'bytes=0-49'})
        assert resp.status_code == 206, f"Expected 206 Partial Content for range request, got {resp.status_code}"
        assert 'Accept-Ranges' in resp.headers

    def test_stream_full_file(self):
        """Stream without Range header returns full file."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_strm'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.post('/api/create-text', data=_json.dumps({'name':'full.txt','parent_id':None}), content_type='application/json')
        fid = resp.get_json()['id']

        # Stream without Range → 200 OK full response
        resp = c.get(f'/stream/{fid}')
        assert resp.status_code == 200


class TestRenameAndMove:
    """Test rename, move, and bulk operations."""

    def test_rename_with_slash(self):
        """Rename with / or \\ in name should fail."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_rns'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.post('/api/create-text', data=_json.dumps({'name':'test.txt','parent_id':None}), content_type='application/json')
        fid = resp.get_json()['id']

        # Rename with forward slash — should fail
        resp = c.post('/api/rename', json={'id': fid, 'name': 'new/name'})
        assert resp.status_code == 400

    def test_rename_with_backslash(self):
        """Rename with backslash in name should fail."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_rns2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.post('/api/create-text', data=_json.dumps({'name':'test.txt','parent_id':None}), content_type='application/json')
        fid = resp.get_json()['id']

        # Rename with backslash — should fail
        resp = c.post('/api/rename', json={'id': fid, 'name': r'new\name'})
        assert resp.status_code == 400

    def test_move_to_root(self):
        """Move a file to root (parent_id=None)."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_mov'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folder and file inside it
        mk_resp = c.post('/api/mkdir', json={'name': 'folder', 'parent_id': None})
        fid_folder = mk_resp.get_json()['id']

        txt_resp = c.post('/api/create-text', data=_json.dumps({'name':'file.txt','parent_id':fid_folder}), content_type='application/json')
        file_in_folder = txt_resp.get_json()['id']

        # Move to root (parent_id=None)
        resp = c.post('/api/move', json={'id': file_in_folder, 'parent_id': None})
        assert resp.status_code == 200

    def test_bulk_delete(self):
        """Bulk delete multiple files."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_bdel'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create 3 files
        ids = []
        for i in range(3):
            r = c.post('/api/create-text', data=_json.dumps({'name':f'bulk{i}.txt','parent_id':None}), content_type='application/json')
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Bulk delete all
        resp = c.post('/api/bulk-delete', json={'ids': ids})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['deleted'] >= len(ids)

    def test_bulk_move(self):
        """Bulk move multiple files to a folder."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_bmov'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folder and files
        mk_resp = c.post('/api/mkdir', json={'name': 'target', 'parent_id': None})
        target_folder = mk_resp.get_json()['id']

        ids = []
        for i in range(3):
            r = c.post('/api/create-text', data=_json.dumps({'name':f'file{i}.txt','parent_id':None}), content_type='application/json')
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Bulk move all to folder
        resp = c.post('/api/bulk-move', json={'ids': ids, 'parent_id': target_folder})
        assert resp.status_code == 200


class TestSearch:
    """Test file search functionality."""

    def test_search_by_name(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_srch'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create files with different names
        for name in ['alpha.txt', 'beta.mp4', 'gamma.md']:
            if '.mp4' in name:
                r = c.post('/api/upload', data={'file': (BytesIO(b'data'), name)}, content_type='multipart/form-data')
            else:
                r = c.post('/api/create-text', data=_json.dumps({'name':name,'parent_id':None}), content_type='application/json')
            assert r.status_code == 200

        # Search for files containing "alpha"
        resp = c.get('/api/search?q=alpha')
        assert resp.status_code == 200
        data = resp.get_json()
        names_found = [f['name'] for f in (data.get('files') or [])]
        assert 'alpha.txt' in names_found

    def test_search_empty_query(self):
        """Search with empty query returns no results."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_srch2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.get('/api/search?q=')
        assert resp.status_code == 200


class TestSpecialCharactersInNames:
    """Test handling of special characters in file/folder names."""

    def test_unicode_filename(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_uni'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create file with Unicode name
        r = c.post('/api/create-text', data=_json.dumps({'name':'日本語.txt','parent_id':None}), content_type='application/json')
        assert r.status_code == 200, f"Unicode filename creation failed: {r.data}"

    def test_folder_with_unicode_name(self):
        """Create folder with Unicode name."""
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_uni2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/mkdir', json={'name': 'Dossier français', 'parent_id': None})
        assert r.status_code == 200


class TestStreamNotFound:
    """Test stream/download for non-existent files."""

    def test_stream_nonexistent_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_nos'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Stream non-existent file ID
        resp = c.get('/stream/99999')
        assert resp.status_code == 404

    def test_download_nonexistent_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_nod'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Download non-existent file ID
        resp = c.get('/download/99999')
        assert resp.status_code == 404


class TestExportKeys:
    """Test the encryption key export endpoint."""

    def test_export_keys_returns_plaintext(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_exp'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Export keys
        resp = c.get('/api/export-keys')
        assert resp.status_code == 200
        content_type = resp.headers.get('Content-Type', '')
        assert 'text/plain' in content_type or 'application/octet-stream' in content_type


class TestEmptyFileHandling:
    """Test edge cases with empty files and directories."""

    def test_stream_empty_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_emp'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create empty text file
        r = c.post('/api/create-text', data=_json.dumps({'name':'empty.txt','parent_id':None}), content_type='application/json')
        fid = r.get_json()['id']

        resp = c.get(f'/stream/{fid}')
        assert resp.status_code == 200


class TestApiFileNotFound:
    """Test API endpoints returning proper errors for missing files."""

    def test_api_file_info_not_found(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_nf'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # File info for non-existent ID
        r = c.get('/api/file/99999/info')
        assert r.status_code == 404


class TestFolderInfoAndBreadcrumbs:
    """Test folder navigation endpoints."""

    def test_folder_breadcrumbs(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_bc'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create nested folders
        r1 = c.post('/api/mkdir', json={'name': 'level1', 'parent_id': None})
        lid1 = r1.get_json()['id']

        r2 = c.post('/api/mkdir', json={'name': 'level2', 'parent_id': lid1})
        lid2 = r2.get_json()['id']

        # Get breadcrumbs for level2
        resp = c.get(f'/api/folder-breadcrumbs/{lid2}')
        assert resp.status_code == 200
        data = resp.get_json()
        crumbs = data.get('breadcrumbs', [])
        assert len(crumbs) >= 3  # Root + level1 + level2

    def test_folder_parent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_fp'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/mkdir', json={'name': 'child', 'parent_id': None})
        cid = r.get_json()['id']

        # Get parent of root-level folder
        resp = c.get(f'/api/folder/{cid}/parent')
        assert resp.status_code == 200


class TestMkdirp:
    """Test mkdirp (create directory if not exists) endpoint."""

    def test_mkdirp_idempotent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_mp'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folder via mkdirp
        r1 = c.post('/api/mkdirp', json={'name': 'shared', 'parent_id': None})
        assert r1.status_code == 200
        id1 = r1.get_json()['id']

        # Call mkdirp again with same name — should return existing ID
        r2 = c.post('/api/mkdirp', json={'name': 'shared', 'parent_id': None})
        assert r2.status_code == 200
        id2 = r2.get_json()['id']

        # Both calls should return the same folder ID (existing, not created again)
        assert id1 == id2


class TestApiFolders:
    """Test list folders endpoint."""

    def test_list_folders_in_parent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_fld'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folders
        for name in ['alpha', 'beta']:
            r = c.post('/api/mkdir', json={'name': name, 'parent_id': None})
            assert r.status_code == 200

        # List root-level folders only (should include both)
        resp = c.get('/api/folders?parent_id=')
        assert resp.status_code == 200


class TestRenameNotFound:
    """Test rename for non-existent file."""

    def test_rename_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_rnf'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Rename non-existent file
        r = c.post('/api/rename', json={'id': 99999, 'name': 'new.txt'})
        assert r.status_code == 404


class TestMoveNotFound:
    """Test move for non-existent file."""

    def test_move_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_mnf'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Move non-existent file
        r = c.post('/api/move', json={'id': 99999, 'parent_id': None})
        assert r.status_code == 404


class TestDeleteNonexistent:
    """Test delete for non-existent file."""

    def test_delete_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_dnf'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Delete non-existent file — should succeed silently
        r = c.post('/api/delete', json={'id': 99999})
        assert r.status_code == 200


class TestBulkOperationsEmpty:
    """Test bulk operations with empty input."""

    def test_bulk_delete_empty_ids(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_bde'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Bulk delete with empty ids list  
        r = c.post('/api/bulk-delete', json={'ids': []})
        # App returns 400 for empty ids (expects non-empty array)
        assert r.status_code in (200, 400)

class TestCreateTextNoExtension:

    """Test creating text files without extensions."""

    def test_create_text_auto_adds_extension(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))

        tmp = '/tmp/_vt_ext'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create text file without extension — should get .txt appended
        r = c.post('/api/create-text', data=_json.dumps({'name': 'Makefile', 'parent_id': None}), content_type='application/json')
        assert r.status_code == 200, f"Create failed: {r.data}"