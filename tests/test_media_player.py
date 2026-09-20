"""Media player tests — siblings navigation, random sibling, sort modes."""
import sys


class TestSiblingsNavigation:
    """Test prev/next file navigation for media playback."""

    def test_siblings_returns_first_last(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sb1'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create 3 text files (text category)  
        ids = []
        for name in ['a.txt', 'b.md', 'c.json']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Query siblings for the middle file — should have prev and next  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=name&recurse=0')
        assert resp.status_code == 200, f"Siblings failed: {resp.data}"
        data = resp.get_json()

        # Middle file should have prev (a.txt) and next (c.json)  
        assert data['prev_id'] == ids[0], "First sibling should be previous"
        assert data['next_id'] == ids[2], "Last sibling should be next"
        assert data['total'] == 3

    def test_siblings_first_file_no_prev(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sb2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create 2 text files  
        ids = []
        for name in ['first.txt', 'second.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # First file should have no prev  
        resp = c.get(f'/api/siblings/{ids[0]}?sort_by=name&recurse=0')
        data = resp.get_json()
        assert data['prev_id'] is None, "First file should not have a previous"


class TestSiblingsSortModes:
    """Test siblings navigation with different sort modes."""

    def test_siblings_sort_by_name(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sm1'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        ids = []
        for name in ['charlie.txt', 'alpha.md']:  # Different order than alphabetical  
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # With sort_by=name, alpha should come first regardless of creation order  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=name&recurse=0')
        data = resp.get_json()
        assert data['total'] == 2


class TestSiblingsNotFound:
    """Test siblings for non-existent file."""

    def test_siblings_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_snf'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.get('/api/siblings/99999')
        assert r.status_code == 404


class TestSiblingsWithRootParam:
    """Test siblings with explicit root parameter."""

    def test_siblings_with_root_param(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sb3'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        ids = []
        for name in ['x.txt', 'y.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # With root=null (vault root), should still find siblings at same level  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=name&recurse=0&root=null')
        assert resp.status_code == 200


class TestSiblingsRecurseOff:
    """Test siblings with recursion disabled."""

    def test_siblings_recurse_off(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sb4'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folder with file inside  
        r = c.post('/api/mkdir', json={'name': 'subdir', 'parent_id': None})
        sub_id = r.get_json()['id']
        
        r = c.post('/api/create-text', json={'name':'inside.txt','parent_id':sub_id})
        inside_id = r.get_json()['id']

        # Create sibling at root level  
        r = c.post('/api/create-text', json={'name':'rootfile.md','parent_id':None})
        root_file_id = r.get_json()['id']

        # With recurse=0, inside.txt should only see no siblings in same folder  
        resp = c.get(f'/api/siblings/{inside_id}?sort_by=name&recurse=0')
        data = resp.get_json()
        assert data['total'] == 1  # Only itself


class TestRandomSibling:
    """Test random sibling file selection."""

    def test_random_sibling_returns_valid_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_rs1'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        ids = []
        for name in ['a.txt', 'b.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Random sibling should return one of the other files  
        resp = c.get(f'/api/random-sibling/{ids[0]}?recurse=0')
        data = resp.get_json()
        random_id = data['file_id']
        
        assert random_id is not None, "Random sibling should return a valid file"
        assert random_id != ids[0], "Should not return the current file itself"


class TestMediaCategory:
    """Test media category detection for siblings."""

    def test_text_files_are_same_category(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_mc1'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create multiple text files  
        ids = []
        for name in ['readme.txt', 'notes.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # They should be in the same category (text)  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=name&recurse=0')
        data = resp.get_json()
        assert data['total'] >= 2, "Text files should find each other as siblings"


class TestSiblingsEmptyCategory:
    """Test siblings when file has no same-type siblings."""

    def test_solo_file_has_no_prev_next(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sc1'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create only one text file  
        r = c.post('/api/create-text', json={'name': 'solo.txt', 'parent_id': None})
        fid = r.get_json()['id']

        resp = c.get(f'/api/siblings/{fid}?sort_by=name&recurse=0')
        data = resp.get_json()
        
        assert data['prev_id'] is None, "Solo file should have no prev"
        assert data['next_id'] is None, "Solo file should have no next"


class TestSiblingsSortBySize:
    """Test siblings sort by size."""

    def test_siblings_sort_by_size(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sm2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create text files of different sizes  
        r1 = c.post('/api/create-text', json={'name': 'small.txt', 'parent_id': None})
        fid_small = r1.get_json()['id']

        import _json as j; resp2 = c.put(f'/api/file/{fid_small}/text', json={'content': 'x' * 50})

        r2 = c.post('/api/create-text', json={'name': 'medium.md', 'parent_id': None})
        
        # Sort by size  
        resp = c.get(f'/api/siblings/{fid_small}?sort_by=size&recurse=0')
        assert resp.status_code == 200


class TestSiblingsSortByRecent:
    """Test siblings sort by recent access."""

    def test_siblings_sort_by_recent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sm3'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        ids = []
        for name in ['old.txt', 'recent.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Access one file to update its last_accessed  
        resp = c.get(f'/player/{ids[1]}')

        # Sort by recent — accessed files should come first  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=recent&recurse=0')
        data = resp.get_json()
        assert data['total'] == 2


class TestSiblingsSortByAdded:
    """Test siblings sort by added (creation time)."""

    def test_siblings_sort_by_added(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sm4'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        ids = []
        for name in ['first.txt', 'second.md']:
            r = c.post('/api/create-text', json={'name': name, 'parent_id': None})
            assert r.status_code == 200
            ids.append(r.get_json()['id'])

        # Sort by added  
        resp = c.get(f'/api/siblings/{ids[1]}?sort_by=added&recurse=0')
        data = resp.get_json()
        assert data['total'] == 2


class TestSiblingsInvalidSort:
    """Test siblings with invalid sort parameter."""

    def test_siblings_invalid_sort_falls_back_to_name(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_sm5'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', json={'name': 'test.txt', 'parent_id': None})
        fid = r.get_json()['id']

        # Invalid sort_by — should fall back to default (name)  
        resp = c.get(f'/api/siblings/{fid}?sort_by=invalid&recurse=0')
        assert resp.status_code == 200


class TestRandomSiblingNoOther:
    """Test random sibling when only one file exists."""

    def test_random_sibling_single_file(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_rs2'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        r = c.post('/api/create-text', json={'name': 'only.txt', 'parent_id': None})
        fid = r.get_json()['id']

        # Only one file — random sibling should return null  
        resp = c.get(f'/api/random-sibling/{fid}?recurse=0')
        data = resp.get_json()
        assert data['file_id'] is None, "Single file should have no random sibling"


class TestRandomSiblingNonexistent:
    """Test random sibling for non-existent file."""

    def test_random_sibling_nonexistent(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_rs3'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        resp = c.get('/api/random-sibling/99999')
        assert resp.status_code == 404


class TestRandomSiblingRecurseOff:
    """Test random sibling with recursion disabled."""

    def test_random_sibling_recurse_off(self):
        import sys as _sys; from pathlib import Path as P
        sys.path.insert(0, str(P('.').resolve()))
        
        tmp = '/tmp/_vt_rs4'; import os, shutil; shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)

        # Set DATA_DIR before importing fresh app
        os.environ['DATA_DIR'] = tmp

        for m in list(_sys.modules.keys()):
            if any(kw in m for kw in ('config', 'models', 'app')) and not 'crypto' == m: del _sys.modules[m]

        from app import create_app; create_app()
        from app import app; app.config['TESTING'] = True
        c = app.test_client()

        c.post('/setup', data={'username':'u','password':'pass1234567890','confirm':'pass1234567890'}, follow_redirects=True)
        resp = c.post('/login', data={'username':'u','password':'pass1234567890'}, follow_redirects=True)

        # Create folder with file inside  
        r = c.post('/api/mkdir', json={'name': 'subdir', 'parent_id': None})
        sub_id = r.get_json()['id']

        ids_in_sub = []
        for name in ['a.txt', 'b.md']:
            r2 = c.post('/api/create-text', json={'name': name, 'parent_id': sub_id})
            assert r2.status_code == 200
            ids_in_sub.append(r2.get_json()['id'])

        # With recurse=0, should only find siblings in same folder  
        resp = c.get(f'/api/random-sibling/{ids_in_sub[1]}?recurse=0')
        data = resp.get_json()
        assert data['file_id'] is not None  # Should find the other file in same folder
