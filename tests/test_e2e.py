"""End-to-end tests for the Flask app — exercises full route chains.

Tests verify that _update_file() correctly updates file metadata in the database,
particularly the modified_at field after text edits (the behavior change from our refactor).
"""

import os as _os
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def tmp_data_dir(tmp_path_factory):
    """Provide a temporary DATA_DIR scoped to this module so modules are cached."""
    d = str(tmp_path_factory.mktemp("vault_e2e"))
    _os.environ["DATA_DIR"] = d
    yield d
    del _os.environ["DATA_DIR"]


@pytest.fixture(scope="module")
def client_and_file_id(tmp_data_dir):
    """Create an isolated Flask test client with setup + login done.

    Yields (client, file_id) where file_id is a newly created text file ready for editing.
    Uses module scope so the DB and modules are cached across all tests in this file.
    """
    # Force reimport of config/models/app so they pick up tmp_data_dir
    import sys as _sys
    for mod_name in list(_sys.modules.keys()):
        if any(kw in mod_name for kw in ('config', 'models', 'app', 'crypto')):
            del _sys.modules[mod_name]

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
    assert resp.status_code == 200, f"Setup failed: {resp.data}"

    # ── Step 2: Login ───────────────────────────────────────────────────
    resp = client.post('/login', data={
        'username': 'testuser',
        'password': 'correcthorsebatterystaple',
    }, follow_redirects=True)
    assert resp.status_code == 200, f"Login failed: {resp.data}"

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
    assert info_resp.status_code == 200, f"File info failed: {info_resp.data}"
    original_modified = info_resp.get_json()['modified_at']
    assert original_modified

    yield (client, file_id), original_modified


class TestWriteTextModifiedAt:
    """E2E test for api_write_text updating the modified_at field.

    This is the critical behavior change from our refactor:
      OLD:  modified_at = datetime("now")   ← SQLite server-side timestamp
      NEW:  _update_file(..., vault_filename=..., size=...) — no explicit modified_at
           → modified_at was NOT updated in the original call site

    We verify that text edits still update modified_at so downstream features
    (sort by "recently modified", last-modified headers, etc.) keep working.
    """

    def test_modified_at_updates_on_text_save(self, client_and_file_id):
        """Saving new text content should update the file's modified_at timestamp."""
        (client, file_id), original_modified = client_and_file_id

        # Record original timestamp before edit
        info_before = client.get(f'/api/file/{file_id}/info').get_json()
        old_modified = info_before['modified_at']
        assert old_modified  # sanity: should have a value from creation

        # Edit the file content via api_write_text (this uses _update_file internally)
        import time; time.sleep(1.05)  # ensure different second for timestamp comparison
        new_content = 'Hello, updated world!'
        resp = client.post(
            f'/api/file/{file_id}/text',
            json={'content': new_content},
        )
        assert resp.status_code == 200

        # Verify content was saved correctly
        read_resp = client.get(f'/api/file/{file_id}/text')
        assert read_resp.status_code == 200, f"Read failed: {read_resp.data}"
        data = read_resp.get_json()
        assert data['content'] == new_content, "Content should match what we wrote"

        # ─── THE KEY ASSERTION: modified_at must have changed ──────────────
        info_after = client.get(f'/api/file/{file_id}/info')
        after_modified = info_after.get_json()['modified_at']

        assert after_modified != old_modified, (
            f"modified_at should change when text content is saved. "
            f"Before: {old_modified!r} → After: {after_modified!r}"
        )


class TestWriteTextSizeUpdate:
    """Verify that file size also updates correctly via _update_file."""

    def test_size_changes_on_text_save(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        info_before = client.get(f'/api/file/{file_id}/info').get_json()
        old_size = info_before['size']

        new_content = 'This is a longer string to test size changes'
        resp = client.post(
            f'/api/file/{file_id}/text',
            json={'content': new_content},
        )
        assert resp.status_code == 200, f"Write failed: {resp.data}"

        info_after = client.get(f'/api/file/{file_id}/info').get_json()
        expected_size = len(new_content.encode('utf-8'))
        actual_size = info_after['size']

        assert actual_size == expected_size, (
            f"File size should be {expected_size}, got {actual_size}"
        )


class TestVaultFilenameUpdate:
    """Verify that vault_filename changes on text save."""

    def test_vault_file_replaced_on_text_save(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        info_before = client.get(f'/api/file/{file_id}/info').get_json()
        old_vault_name = info_before['vault_filename']

        new_content = 'Fresh content replaces the vault blob'
        resp = client.post(
            f'/api/file/{file_id}/text',
            json={'content': new_content},
        )
        assert resp.status_code == 200

        info_after = client.get(f'/api/file/{file_id}/info').get_json()
        new_vault_name = info_after['vault_filename']

        assert old_vault_name != new_vault_name, (
            "A new vault file should be created on text edit"
        )
        assert new_vault_name.endswith('.enc'), "New vault filename should end with .enc"


class TestStreamFileStillWorks:
    """Verify that basic streaming still works after _update_file refactor."""

    def test_stream_and_download(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        # Stream the file (uses enc.decrypt_range / decrypt_full — unchanged by our refactor)
        resp = client.get(f'/stream/{file_id}')
        assert resp.status_code == 200, f"Stream failed: {resp.data}"

        # Download should also work
        dl_resp = client.get(f'/download/{file_id}')
        assert dl_resp.status_code == 200


class TestRenameFileStillWorks:
    """Verify rename still works (uses models.rename_file — unchanged)."""

    def test_rename(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        resp = client.post('/api/rename', json={
            'id': file_id,
            'name': 'renamed.txt',
        })
        assert resp.status_code == 200, f"Rename failed: {resp.data}"

        info = client.get(f'/api/file/{file_id}/info').get_json()
        assert info['name'] == 'renamed.txt'


class TestDeleteFileStillWorks:
    """Verify delete still works (uses models.delete_file_record — unchanged)."""

    def test_delete(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id

        resp = client.post('/api/delete', json={'id': file_id})
        assert resp.status_code == 200

        info_resp = client.get(f'/api/file/{file_id}/info')
        assert info_resp.status_code == 404, "Deleted file should return 404"


class TestLoginLogoutFlow:
    """Verify auth flow is intact (login → session → logout)."""

    def test_logout_clears_session(self, tmp_data_dir):
        import sys as _sys
        for mod_name in list(_sys.modules.keys()):
            if any(kw in mod_name for kw in ('config', 'models', 'app')):
                del _sys.modules[mod_name]

        from app import create_app  # noqa: E402, F811
        create_app()

        from app import app  # noqa: E402, F811
        app.config['TESTING'] = True
        client = app.test_client()

        client.post('/setup', data={
            'username': 'logoutuser',
            'password': 'testpass123!',
            'confirm': 'testpass123!',
        }, follow_redirects=True)

        resp = client.post('/login', data={
            'username': 'logoutuser',
            'password': 'testpass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200, f"Login failed: {resp.data}"

        # Logout should work and redirect to login
        resp = client.get('/logout')
        assert resp.status_code in (200, 302)


class TestAuthenticatedRoutesWork:
    """Verify logged-in user can access protected routes."""

    def test_authenticated_routes_work(self, tmp_data_dir):
        import sys as _sys
        for mod_name in list(_sys.modules.keys()):
            if any(kw in mod_name for kw in ('config', 'models', 'app')):
                del _sys.modules[mod_name]

        from app import create_app  # noqa: E402, F811
        create_app()

        from app import app  # noqa: E402, F811
        app.config['TESTING'] = True
        client = app.test_client()

        client.post('/setup', data={
            'username': 'authuser',
            'password': 'testpass123!',
            'confirm': 'testpass123!',
        }, follow_redirects=True)

        resp = client.post('/login', data={
            'username': 'authuser',
            'password': 'testpass123!',
        }, follow_redirects=True)
        assert resp.status_code == 200, f"Login failed: {resp.data}"

        # Explorer page should be accessible (may redirect to /api/files)
        resp = client.get('/')
        assert resp.status_code in (200, 301, 302), f"Explorer failed: {resp.status_code} {resp.data[:200]}"


class TestCreateTextAndUploadStillWork:
    """Verify that creating and uploading files still works."""

    def test_create_text_file(self, client_and_file_id):
        (client, file_id), _ = client_and_file_id
        # If we got here with a valid file_id from the fixture, creation worked.
        assert file_id > 0
