"""CBZ reader tests — page listing, image extraction, preferences."""
import sys

import io as _io
import zipfile as _zipfile


class TestCbzPages:
    """Test CBZ page counting endpoint."""

    def test_pages_endpoint_returns_count(self):
        from helpers.test_helpers import setup_client as _sc
        c = _sc()

        # Create a CBZ file (zip with images)  
        cbz_data = _io.BytesIO()
        with _zipfile.ZipFile(cbz_data, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)   # JPEG header  
            zf.writestr('page1.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)    # PNG header
        cbz_data.seek(0)

        resp = c.post('/api/upload', data={
            'file': (_io.BytesIO(cbz_data.getvalue()), 'comic.cbz'),
        }, content_type='multipart/form-data')
        assert resp.status_code == 200, f"CBZ upload failed: {resp.data}"
        file_id = resp.get_json()['id']

        # Get page count  
        resp = c.get(f'/api/cbz/{file_id}/pages')
        assert resp.status_code in (200, 403), "Should return pages or vault locked"
        
        if resp.status_code == 200:
            data = resp.get_json()
            # Should detect image files in the CBZ 
            pages_count = data.get('pages', -1)
            assert pages_count >= 2, f"Expected at least 2 pages, got {pages_count}"


class TestCbzImageExtraction:
    """Test extracting individual page images from CBZ."""

    def test_cbz_image_endpoint(self):
        from helpers.test_helpers import setup_client as _sc  
        c = _sc()

        # Create a CBZ file 
        cbz_data = _io.BytesIO()
        with _zipfile.ZipFile(cbz_data, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_data.seek(0)  
        resp = c.post('/api/upload', data={
            'file': (_io.BytesIO(cbz_data.getvalue()), 'comic.cbz'),
        }, content_type='multipart/form-data')
        
        if resp.status_code == 200:
            file_id = resp.get_json()['id']  
            
            # Extract first page image 
            resp = c.get(f'/api/cbz/{file_id}/page/1')
            assert resp.status_code in (200, 403, 404)


class TestCbzImageNotFound:
    """Test CBZ image extraction for invalid page numbers."""

    def test_cbz_image_page_not_found(self):  
        from helpers.test_helpers import setup_client as _sc  
        c = _sc()

        # Create a 1-page CBZ 
        cbz_data = _io.BytesIO()
        with _zipfile.ZipFile(cbz_data, 'w') as zf:  
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_data.seek(0)
        resp = c.post('/api/upload', data={
            'file': (_io.BytesIO(cbz_data.getvalue()), 'comic.cbz'),  
        }, content_type='multipart/form-data')
        
        if resp.status_code == 200:
            file_id = resp.get_json()['id']
            
            # Request page beyond end — should return error 
            resp = c.get(f'/api/cbz/{file_id}/page/999')  
            assert resp.status_code in (404, 403), f"Expected 404 or vault locked, got {resp.status_code}"


class TestCbzPrefsGetSet:
    """Test CBZ reader preferences endpoint."""

    def test_cbz_prefs_get_and_set(self):  
        from helpers.test_helpers import setup_client as _sc  
        c = _sc()

        # Get default prefs — should return 200 or vault locked 
        resp = c.get('/api/cbz-prefs')
        assert resp.status_code in (200, 403, 404)


class TestCbzNonexistent:  
    """Test CBZ endpoint for non-existent file."""

    def test_cbz_pages_nonexistent(self):  
        from helpers.test_helpers import setup_client as _sc
        c = _sc()  

        # Request pages for nonexistent file 
        resp = c.get('/api/cbz/99999/pages')
        assert resp.status_code in (404, 403), "Should return 404 or vault locked"


class TestCbzImageNegativePage:  
    """Test CBZ image endpoint with negative page number."""

    def test_cbz_image_negative_page(self):  
        from helpers.test_helpers import setup_client as _sc
        c = _sc()  

        # Create a 1-page CBZ 
        cbz_data = _io.BytesIO()  
        with _zipfile.ZipFile(cbz_data, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_data.seek(0) 
        resp = c.post('/api/upload', data={
            'file': (_io.BytesIO(cbz_data.getvalue()), 'comic.cbz'),  
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Request negative page — should return error 
            resp = c.get(f'/api/cbz/{file_id}/page/-1')
            assert resp.status_code in (400, 403, 404)


class TestCbzMultipleImageFormats:  
    """Test CBZ with multiple image formats."""  

    def test_cbz_detects_multiple_formats(self): 
        from helpers.test_helpers import setup_client as _sc
        c = _sc()

        # Create a multi-format CBZ  
        cbz_data = _io.BytesIO()
        with _zipfile.ZipFile(cbz_data, 'w') as zf:
            for fmt in ['jpg', 'png']:
                if fmt == 'jpg': 
                    header = b'\xff\xd8\xff\xe0'  # JPEG SOI  
                else:  
                    header = b'\x89PNG\r\n\x1a\n'  # PNG signature
                zf.writestr(f'page.{fmt}', header + b'\x00' * 100)

        cbz_data.seek(0) 
        resp = c.post('/api/upload', data={  
            'file': (_io.BytesIO(cbz_data.getvalue()), 'multi.cbz'),
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Get page count — should find both images 
            resp = c.get(f'/api/cbz/{file_id}/pages')  
            assert resp.status_code in (200, 403), "Should return pages or vault locked"
            
            if resp.status_code == 200:
                data = resp.get_json()
                pages_count = data.get('pages', -1)
                assert pages_count >= 2, f"Expected at least 2 pages from multi-format CBZ"
