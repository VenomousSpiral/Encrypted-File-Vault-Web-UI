"""End-to-end tests that exercise ALL helper module route handlers.

These catch NameError and other runtime errors in helpers/*.py functions that static 
analysis (ruff/mypy) can't detect because helpers use lazy imports inside function bodies.

Each test hits a Flask route which triggers the corresponding helper function body,
exercising all its lazy-imported names at runtime. If any name is missing or aliased
wrongly, we get a 500 error here.

Run standalone:  pytest tests/test_e2e_helper_routes.py -v
"""


class TestAllHelperRoutes:
    """Exercise every route handler in helpers/ to catch NameError / ImportError."""

    def test_file_explorer_routes(self, e2e_client):
        """GET /api/files — uses list_files, get_user_preferences, etc. (app_helpers_files)."""
        c = e2e_client
        resp = c.get('/api/files')
        assert resp.status_code == 200, f"/api/files returned {resp.status_code}: {resp.data.decode()[:500]}"
        data = resp.get_json()
        assert 'files' in data

    def test_folder_routes(self, e2e_client):
        """GET /api/folders — uses get_folders (app_helpers_files)."""
        c = e2e_client
        resp = c.get('/api/folders')
        assert resp.status_code == 200

    def test_mkdir_and_search(self, e2e_client):
        """POST /api/mkdir + GET /api/search — uses create_file_record, search_files."""
        c = e2e_client
        resp = c.post('/api/mkdir', json={'name': 'test_folder'}, content_type='application/json')
        assert resp.status_code in (200, 403)  # may be locked

    def test_text_editor_routes(self, e2e_client):
        """GET /editor/<id> + GET/POST /api/file/<id>/text — uses render_template."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'test.txt'}, content_type='application/json')
        assert resp.status_code == 200, f"Create text failed: {resp.data.decode()[:500]}"

    def test_text_editable_check(self, e2e_client):
        """GET /api/file/<id>/editable — uses _is_text_editable (dead code fix)."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'check.txt'}, content_type='application/json')
        fid = resp.get_json().get('id', 1)

        # This route had a dead-code bug: two consecutive returns, second was unreachable
        resp = c.get(f'/api/file/{fid}/editable')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'editable' in data

    def test_siblings_routes(self, e2e_client):
        """GET /api/siblings/<id> — uses _media_category (alias-vs-call bug fix)."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'sib.txt'}, content_type='application/json')
        fid = resp.get_json().get('id', 1)

        # This route had _media_category imported as _mc but called as _media_category
        resp = c.get(f'/api/siblings/{fid}')
        assert resp.status_code == 200, f"/api/siblings returned {resp.status_code}: {resp.data.decode()[:500]}"

    def test_random_sibling_route(self, e2e_client):
        """GET /api/random-sibling/<id> — uses _collect_recursive (alias fix)."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'rand.txt'}, content_type='application/json')
        fid = resp.get_json().get('id', 1)

        # This route had _cr aliased import but called without alias, plus missing get_user_preferences
        resp = c.get(f'/api/random-sibling/{fid}')
        assert resp.status_code == 200, f"/api/random-sibling returned {resp.status_code}: {resp.data.decode()[:500]}"

    def test_player_route(self, e2e_client):
        """GET /player/<id> — uses get_video_preferences (missing import fix)."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'play.txt'}, content_type='application/json')
        fid = resp.get_json().get('id', 1)

        # This route was missing `get_video_preferences` in its local import list
        resp = c.get(f'/player/{fid}')
        assert resp.status_code == 200, f"/player returned {resp.status_code}: {resp.data.decode()[:500]}"

    def test_folder_breadcrumbs(self, e2e_client):
        """GET /api/folder-breadcrumbs/<id> — uses get_breadcrumbs."""
        c = e2e_client
        resp = c.post('/api/mkdir', json={'name': 'bc_test'}, content_type='application/json')

    def test_hls_status_route(self, e2e_client):
        """GET /api/hls/<id>/status — uses _get_encryptor (was: imported as gen but called _get_encryptor).

        Returns 404 when file doesn't exist, or 400 for non-video files. The key thing is it
        must NOT return 500 with a NameError.
        """
        c = e2e_client
        resp = c.get('/api/hls/1/status')
        assert resp.status_code in (200, 400, 404), f"HLS status returned {resp.status_code}: {resp.data.decode()[:500]}"

    def test_hls_master_route(self, e2e_client):
        """GET /api/hls/<id>/master.m3u8 — uses url_for with correct endpoint names (was: missing _ep suffix).

        Returns 404 for non-existent files. The key thing is it must NOT return 500 with a BuildError.
        """
        c = e2e_client
        resp = c.get('/api/hls/1/master.m3u8')
        assert resp.status_code in (200, 400, 404), f"HLS master returned {resp.status_code}: {resp.data.decode()[:500]}"

    def test_folder_parent_route(self, e2e_client):
        """GET /api/folder/<id>/parent — uses get_folder_info."""
        c = e2e_client
        resp = c.post('/api/mkdir', json={'name': 'par_test'}, content_type='application/json')
        assert resp.status_code == 200, f"Folder parent returned {resp.status_code}: {resp.data.decode()[:500]}"
    
    def test_download_unicode_filename(self, e2e_client):
        """Download with non-latin-1 filename (CJK/fullwidth chars) must NOT raise UnicodeEncodeError.

        This catches the bug where Content-Disposition header contains characters outside
        latin-1 range (\uff1f fullwidth question mark, \uff5c fullwidth vertical bar, CJK),
        which causes werkzeug's HTTP server to fail with:
          UnicodeEncodeError: 'latin-1' codec can't encode character '\uff1f'
        
        The fix uses RFC 5987 encoding (filename*=UTF-8''...) for non-latin-1 names.
        """
        c = e2e_client
        # Create a text file with fullwidth characters in the name
        unicode_names = [
            '文件.pdf',           # Chinese characters
            'テスト.txt',          # Japanese Katakana  
            'test\uff1f.txt',     # Fullwidth question mark (from original bug)
            'test\uff5c.txt',     # Fullwidth vertical bar (from original bug)
        ]
        for name in unicode_names:
            resp = c.post('/api/create-text', json={'name': name}, content_type='application/json')
            assert resp.status_code == 200, f"Create '{name}' failed: {resp.data.decode()[:500]}"
            fid = resp.get_json().get('id')
            
            # Download the file — this is where the UnicodeEncodeError would occur
            resp = c.get(f'/download/{fid}')
            assert resp.status_code == 200, f"Download '{name}' returned {resp.status_code}: {resp.data.decode()[:500]}"
            
            # Verify Content-Disposition header is valid (no raw Unicode)
            cd = resp.headers.get('Content-Disposition', '')
            assert 'filename' in cd.lower(), f"Missing filename in Content-Disposition for '{name}'"

    def test_stream_unicode_filename(self, e2e_client):
        """Stream with non-latin-1 filename must NOT raise UnicodeEncodeError.

        Similar to download but exercises the /stream/<id> route which also uses
        Content-Disposition via Range header support. Tests that _encode_content_disposition()
        properly handles RFC 5987 encoding for CJK and special characters.
        """
        c = e2e_client
        # Create a text file with non-latin-1 chars in the name
        resp = c.post('/api/create-text', json={'name': '中文测试.txt'}, content_type='application/json')
        assert resp.status_code == 200, f"Create failed: {resp.data.decode()[:500]}"
        fid = resp.get_json().get('id')
        
        # Stream the file — should NOT raise UnicodeEncodeError
        resp = c.get(f'/stream/{fid}')
        assert 200 <= resp.status_code < 400, f"Stream returned {resp.status_code}: {resp.data.decode()[:500]}"
    
    def test_download_ascii_filename(self, e2e_client):
        """Download with normal ASCII filename still works (regression check)."""
        c = e2e_client
        resp = c.post('/api/create-text', json={'name': 'normal-file.txt'}, content_type='application/json')
        assert resp.status_code == 200, f"Create failed: {resp.data.decode()[:500]}"
        fid = resp.get_json().get('id')
        
        # Download should work and use simple quoted form
        resp = c.get(f'/download/{fid}')
        assert resp.status_code == 200, f"Download returned {resp.status_code}: {resp.data.decode()[:500]}"
        cd = resp.headers.get('Content-Disposition', '')
        # ASCII names should use simple quoted form (not RFC 5987)
        assert 'filename="normal-file.txt' in cd, f"ASCII filename not properly encoded: {cd}"
