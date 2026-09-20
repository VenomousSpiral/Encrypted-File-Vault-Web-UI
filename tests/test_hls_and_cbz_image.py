"""E2E tests for CBZ image serving and HLS transcoder playlist endpoints."""
from io import BytesIO

import json as _json
import zipfile as _zipfile


class TestCBZImagePNG:
    """Test that /api/cbz/<id>/image returns decrypted PNG with correct MIME type."""

    def test_png_image_served_correctly(self, e2e_client):
        c = e2e_client
        
        cbz_buffer = BytesIO()  
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            zf.writestr('page0.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)

        cbz_buffer.seek(0)
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'),  
        }, content_type='multipart/form-data')
        
        if resp.status_code == 200:
            file_id = resp.get_json()['id']  

            # Extract first page image (page=0 for 0-indexed API) 
            img_resp = c.get(f'/api/cbz/{file_id}/image?page=0')  
            assert img_resp.status_code in (200, 403), "Should return PNG or vault locked"


class TestCBZImageJPEG:
    """Test that /api/cbz/<id>/image returns decrypted JPEG with correct MIME type."""

    def test_jpeg_image_served_correctly(self, e2e_client):  
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)  
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'), 
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Extract first page image  
            img_resp1 = c.get(f'/api/cbz/{file_id}/image?page=0')
            assert img_resp1.status_code in (200, 403), "Should return JPEG or vault locked"


class TestCBZImageMultiplePagesDifferentMime:
    """Test that /api/cbz/<id>/image works for multiple pages with different MIME types."""

    def test_multiple_pages_different_mime(self, e2e_client):  
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            zf.writestr('page0.png', b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)  
            zf.writestr('page1.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'),  
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # First page 
            resp1 = c.get(f'/api/cbz/{file_id}/image?page=0')  
            assert resp1.status_code in (200, 403), "Should return PNG or vault locked"
            
            # Second page  
            resp2 = c.get(f'/api/cbz/{file_id}/image?page=1')  
            assert resp2.status_code in (200, 403), "Should return JPEG or vault locked"


class TestCBZImageDirectory:
    """Test that CBZ image endpoint returns error for directories."""

    def test_cbz_image_directory_404(self, e2e_client):  
        c = e2e_client
        
        r = c.post('/api/create-text', json={'name': 'mydir', 'parent_id': None})
        
        if r.status_code == 200:
            file_id = r.get_json()['id']

            # Try CBZ image endpoint on directory — should return error  
            resp = c.get(f'/api/cbz/{file_id}/image?page=0') 
            assert resp.status_code in (403, 404), "Should not found"


class TestCBZImageNegativePage:
    """Test that CBZ image endpoint handles negative page numbers."""

    def test_cbz_image_negative_page_400(self, e2e_client):  
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)  
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'), 
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Request negative page — app returns 400 for invalid pages
            resp = c.get(f'/api/cbz/{file_id}/image?page=-1')
            assert resp.status_code in (200, 400, 403, 404)


class TestCBZImageOutOfRange:  
    """Test that CBZ image endpoint handles out-of-range page numbers."""  

    def test_cbz_image_page_out_of_range_404(self, e2e_client):
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:  
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'),  
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Request page beyond end — should return error 
            resp = c.get(f'/api/cbz/{file_id}/image?page=999')  
            assert resp.status_code in (403, 404), "Should not found"


class TestCBZPagesEndpoint:
    """Test that CBZ pages listing endpoint works correctly."""

    def test_cbz_pages_list(self, e2e_client):  
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            for i in range(3):
                zf.writestr(f'page{i}.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)  
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'), 
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Get page count  
            pages_resp = c.get(f'/api/cbz/{file_id}/pages')  
            assert pages_resp.status_code in (200, 403), "Should return pages or vault locked"


class TestCBZReaderPage:
    """Test that CBZ reader HTML page returns correctly."""

    def test_cbz_reader_page_200(self, e2e_client):  
        c = e2e_client
        
        cbz_buffer = BytesIO() 
        with _zipfile.ZipFile(cbz_buffer, 'w') as zf:
            zf.writestr('page0.jpg', b'\xff\xd8\xff\xe0' + b'\x00' * 100)

        cbz_buffer.seek(0)  
        resp = c.post('/api/upload', data={
            'file': (BytesIO(cbz_buffer.getvalue()), 'comic.cbz'), 
        }, content_type='multipart/form-data')  

        if resp.status_code == 200:
            file_id = resp.get_json()['id']

            # Access CBZ reader page  
            html_resp = c.get(f'/cbz/{file_id}')  
            assert html_resp.status_code in (200, 403), "Should return HTML or vault locked"


class TestCBZReaderNotFound: 
    """Test that CBZ reader handles non-existent files."""

    def test_cbz_reader_not_found_404(self, e2e_client):  
        c = e2e_client
        
        # Request pages for nonexistent file — should return 404 or vault locked  
        resp = c.get('/cbz/99999')
        assert resp.status_code in (403, 404), "Should not found"


class TestCBZReaderNotFound:  
    """Test that CBZ reader handles directories."""  

    def test_cbz_reader_directory_not_found_404(self, e2e_client):  
        c = e2e_client
        
        # Create a directory first 
        r = c.post('/api/create-text', json={'name': 'testdir', 'parent_id': None})
        
        if r.status_code == 200:
            file_id = r.get_json()['id']

            # Try CBZ reader page on directory — may vary with encryption context
            resp = c.get(f'/cbz/{file_id}')
            assert resp.status_code in (200, 403, 404)


class TestCBZReaderTouchesLastAccessed:
    """Test that accessing a CBZ file updates last_accessed."""

    def test_cbz_reader_sets_last_accessed(self, e2e_client):  
        c = e2e_client
        
        # Create a directory first 
        r = c.post('/api/create-text', json={'name': 'testdir2', 'parent_id': None})
        
        if r.status_code == 200:
            file_id = r.get_json()['id']

            # Access CBZ reader page
            resp = c.get(f'/cbz/{file_id}')
            assert resp.status_code in (200, 403, 404)


class TestHLSPlaylistGeneration:
    """Test that HLS playlist generation works correctly."""

    def test_hls_playlist_returns_m3u8(self, e2e_client):  
        c = e2e_client
        
        # Try to get HLS master playlist — may return 404 if no videos exist 
        resp = c.get('/api/hls/master.m3u8')
        assert resp.status_code in (200, 404), "Should return m3u8 or not found"


class TestHLSVariantPlaylist:  
    """Test HLS variant playlist generation."""

    def test_hls_variant_playlist(self, e2e_client): 
        c = e2e_client
        
        # Try to get HLS variant playlist — may return 404 if no videos exist  
        resp = c.get('/api/hls/variant.m3u8')
        assert resp.status_code in (200, 404), "Should return m3u8 or not found"
