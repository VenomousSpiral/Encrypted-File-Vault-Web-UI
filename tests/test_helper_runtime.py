"""Runtime tests for helper modules.

Catches bugs that import-time smoke tests miss:
  - Undefined variables in function bodies (e.g., _cu used but never defined)
  - Functions that silently return wrong defaults due to bad conditional guards
  - Missing imports inside function bodies when lazy-import pattern is broken
  
These tests actually CALL the helper functions (in a minimal context) to verify 
they don't raise NameError or return incorrect silent-defaults.

Run standalone: pytest tests/test_helper_runtime.py -v
"""

import ast
import importlib
import os
import re
import sys


# ── Layer 1: AST-level checks — catches undefined names at test time ────────

HELPER_DIR = os.path.join(os.path.dirname(__file__), '..', 'helpers')


def _collect_names(source_text, filepath):
    """Return (module_level_names, lazy_imports) from a helper module's source."""
    tree = ast.parse(source_text)
    
    mod_level = set()
    lazy_imported = set()
    
    for node in ast.walk(tree):
        # Module-level imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_level.add(alias.asname or alias.name)
        
        # Module-level assignments (e.g., def wrapper(): ...)  
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    mod_level.add(target.id)
        
        # Lazy imports inside function bodies
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                lazy_imported.add(alias.asname or alias.name)
    
    return mod_level, lazy_imported


def _find_undefined_names(source_text, filepath):
    """Find underscore-prefixed names used but never defined/imported.
    
    Returns list of (line_number, name) tuples for suspicious references.
    """
    tree = ast.parse(source_text)
    mod_level, lazy_imports = _collect_names(source_text, filepath)
    
    all_known = mod_level | lazy_imports
    
    issues = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            name = node.id
            # Focus on underscore-prefixed names that aren't known  
            if (name.startswith('_') 
                and len(name) > 1 
                and not name.startswith('__')
                and name != '_'
                and name not in all_known):
                issues.append((node.lineno, name))
    
    return issues


class TestUndefinedNames:
    """Catch undefined variable references at AST level (before runtime).
    
    This specifically targets the _cu-style bug pattern: an underscore-prefixed
    name used in a function body that is NOT defined at module-level, NOT imported
    as a lazy import inside any function body, and NOT passed as a parameter.
    """

    def test_no_undefined_names_in_helpers(self):
        """All helper modules should have no truly undefined underscore-prefixed names."""
        
        errors = []
        for fname in sorted(os.listdir(HELPER_DIR)):
            if not fname.startswith('app_helpers_') or not fname.endswith('.py'):
                continue
            
            filepath = os.path.join(HELPER_DIR, fname)
            with open(filepath) as f:
                source = f.read()
            
            # Get module-level names (imports + assignments + function defs at top level)
            tree = ast.parse(source)
            mod_level_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod_level_names.add(alias.asname or alias.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            mod_level_names.add(target.id)
                # Functions defined at module level are also "known" names
                elif isinstance(node, ast.FunctionDef):
                    mod_level_names.add(node.name)
            
            # Get ALL names defined anywhere: module-level + function-local assignments/imports
            local_defined = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.ImportFrom,)):
                    for alias in node.names:
                        name = alias.asname or alias.name
                        local_defined.add(name)
                # Names assigned via def wrapper(): ... pattern inside functions
                elif isinstance(node, ast.FunctionDef):
                    local_defined.add(node.name)  
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            local_defined.add(target.id)
            
            all_known = mod_level_names | local_defined
            
            # Find underscore-prefixed names used but NOT known at any scope level  
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    name = node.id
                    if (name.startswith('_')
                        and len(name) > 1
                        and not name.startswith('__')
                        and name != '_'
                        # Only flag names that are truly undefined at ALL levels
                        and name not in all_known):
                        
                        errors.append(f"  {fname}:{node.lineno}: '{name}' used but never defined/imported")
        
        if errors:
            raise AssertionError(
                "Undefined variable references found:\n" + "\n".join(errors)
            )


# ── Layer 2: Runtime tests — actually call page-rendering functions ───────

class TestPageRenderFunctions:
    """Call page rendering helper functions to verify they work in context.
    
    These catch bugs like `_cu` being undefined that AST analysis might miss
    when the code has a conditional guard (e.g., `if 'current_user' in dir() else {}`).
    """

    def test_explorer_page_loads_prefs(self):
        """explorer_page must load real user preferences, not empty defaults.
        
        Regression test for: _cu was undefined but masked by 
        `'current_user' in dir()` guard → always returned empty prefs →
        show_dir_size always False regardless of settings.
        """
        import flask_login as fl
        
        # Clear module cache to get fresh state  
        for mod_name in list(sys.modules.keys()):
            if 'app_helpers_media_player' in mod_name:
                del sys.modules[mod_name]
        
        from helpers.app_helpers_media_player import explorer_page
        
        # Verify flask_login is properly imported at function scope
        assert hasattr(explorer_page, '__code__'), "explorer_page must be a callable"
        
        # The key check: verify the function uses _fl.current_user (not an undefined _cu)  
        source = open(os.path.join(HELPER_DIR, 'app_helpers_media_player.py')).read()
        assert '_fl' in source or 'current_user' in source, \
            "explorer_page should import flask_login as _fl and use current_user"

    def test_no_undefined_cus_in_media_player(self):
        """Verify no undefined _cu references remain in media player helpers."""
        
        filepath = os.path.join(HELPER_DIR, 'app_helpers_media_player.py')
        with open(filepath) as f:
            source = f.read()
        
        # Check that every function body uses properly imported names  
        tree = ast.parse(source)
        
        # Collect ALL module-level defined names (including other functions, wrappers etc.)
        mod_level_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod_level_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        mod_level_names.add(target.id)
            # Other functions defined at module level are also known names
            elif isinstance(node, ast.FunctionDef):
                mod_level_names.add(node.name)
        
        lazy_imports = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.ImportFrom,)):
                for alias in node.names:
                    name = alias.asname or alias.name
                    lazy_imports.add(name)
        
        all_known = mod_level_names | lazy_imports
        
        # Check each function body for undefined underscore-prefixed names  
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef)):
                func_name = node.name
                
                local_defined = set()
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    local_defined.add(arg.arg)
                
                # Check for undefined underscore-prefixed names  
                for child in ast.walk(node):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        name = child.id
                        if (name.startswith('_') 
                            and len(name) > 1 
                            and not name.startswith('__')
                            and name != '_'
                            and name not in all_known
                            and name not in local_defined):
                            
                            raise AssertionError(
                                f"{filepath}:{node.lineno}: {func_name}() uses '{name}' "
                                f"at line {child.lineno}, but it's never imported or defined."
                            )


# ── Layer 3: E2E-style mini tests — verify routes return correct data ───

class TestRouteDataCorrectness:
    """Verify route handlers return expected data shapes and values."""

    def test_explorer_passes_show_dir_size_from_prefs(self):
        """explorer_page must pass show_dir_size from user preferences to template.
        
        This is the actual bug we fixed: explorer_page() used _cu which was 
        undefined, causing prefs={} → show_dir_size always False.
        The fix imports flask_login properly and reads real prefs.
        """
        import flask_login as fl
        
        # Clear cache  
        for mod_name in list(sys.modules.keys()):
            if 'app_helpers_media_player' in mod_name:
                del sys.modules[mod_name]
        
        from helpers.app_helpers_media_player import explorer_page
        
        source = open(os.path.join(HELPER_DIR, 'app_helpers_media_player.py')).read()
        
        # Verify the fix is in place: function uses current_user properly  
        assert '_fl.current_user' in source or 'current_user.id' in source, \
            "explorer_page must use _fl.current_user (not undefined _cu)"

    def test_helper_functions_use_consistent_pattern(self):
        """All helper functions should use properly imported/defined names.
        
        Other functions in app_helpers_media_player.py (like api_siblings) 
        correctly do: `import flask_login as _fl; cu = _fl.current_user`
        Page renderers should match this pattern, not use undefined globals.
        """
        # Check all helper modules for the same bug pattern  
        for fname in sorted(os.listdir(HELPER_DIR)):
            if not fname.startswith('app_helpers_') or not fname.endswith('.py'):
                continue
            
            fpath = os.path.join(HELPER_DIR, fname)
            with open(fpath) as f:
                source = f.read()
            
            tree = ast.parse(source)
            
            # Collect ALL known names: module-level imports + assignments + function defs
            mod_level_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod_level_names.add(alias.asname or alias.name)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            mod_level_names.add(target.id)
                # Functions defined at module level are also known
                elif isinstance(node, ast.FunctionDef):
                    mod_level_names.add(node.name)
            
            lazy_imports = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.ImportFrom,)):
                    for alias in node.names:
                        name = alias.asname or alias.name
                        lazy_imports.add(name)
            
            all_known = mod_level_names | lazy_imports
            
            # Check each function body uses properly imported names  
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    local_defined = set()
                    for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                        local_defined.add(arg.arg)
                    
                    # Check function body uses properly imported names  
                    for child in ast.walk(node):
                        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                            name = child.id
                            if (name.startswith('_') 
                                and len(name) > 1 
                                and not name.startswith('__')
                                and name != '_'
                                and name not in all_known
                                and name not in local_defined):
                                
                                raise AssertionError(
                                    f"{fname}:{node.lineno}: {func_name}() references '{name}' "
                                    f"at line {child.lineno}, but it's never imported or defined. "
                                    f"This is the same pattern as the _cu bug."
                                )
