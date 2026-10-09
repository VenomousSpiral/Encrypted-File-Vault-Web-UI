"""Direct-import smoke tests for helper modules.

Two-layer defense against refactor bugs (NameError, missing imports):
  Layer 1: Module-level import test — catches ImportError at import time  
  Layer 2: Ruff F401 on helpers/ — catches unused imports after refactor
  
These catch issues that e2e tests miss because they exercise routes through a broken fixture,
or skip the route entirely (redirect before hitting helper code).

Run standalone:  pytest tests/test_helper_imports.py -v
"""

import importlib
import re
import subprocess
import sys


# Modules we want to verify can be imported without raising NameError/ImportError  
HELPER_MODULES = [
    "core.auth",
    "core.files_api",  
    "core.streaming",
    "core.media_player",
    "core.text_editor",
    "core.preferences",
    "core.audio_reencode",
    "core.users_api",
]


def _clear_module_cache(mod_name: str):
    """Remove a module and all its submodules from sys.modules."""
    prefix = mod_name + "."
    to_remove = [m for m in sys.modules if m == mod_name or m.startswith(prefix)]
    for m in to_remove:
        del sys.modules[m]


class TestCoreModuleImports:
    """Each core module must import cleanly — no NameError, ImportError."""

    def test_core_modules_import_cleanly(self):
        """All helper modules should be importable without exceptions.

        This catches bugs like:
          - Missing top-level imports (e.g., forgot to add `import config`)
          - Broken relative paths in lazy imports (`from .nonexistent import foo`)  
          - Circular dependency issues introduced by refactor
        """
        errors = {}

        for mod_name in HELPER_MODULES:
            # Fresh import each time to catch inter-module pollution issues
            _clear_module_cache(mod_name.split(".")[0])  # clear 'helpers' tree
            try:
                importlib.import_module(mod_name)
            except Exception as exc:
                errors[mod_name] = f"{type(exc).__name__}: {exc}"

        if errors:
            msg_lines = ["Helper imports failed:\n"]
            for name, err in errors.items():
                msg_lines.append(f"  - {name}: {err}")
            raise AssertionError("\n".join(msg_lines))


class TestRuffTopLevelNames:
    """Run ruff to catch unused imports (F401) on core modules.

    This catches leftover imports from refactor — when you rename/move a function and forget 
    to update the import line, ruff will flag it immediately in CI. We check all core/ files
    because they are the main targets during refactors.

    Note: F821 (undefined name) is noisy here because modules use lazy imports inside function bodies
    which ruff can't trace, so we only check F401 for the refactor-defense guarantee.
    """

    def test_ruff_no_unused_imports_in_core(self):
        """Ruff must report zero F401 (unused import) errors on core/ modules.
        
        Note: We only check F401 because F821 (undefined name) is noisy —
        lazy imports inside function bodies use names ruff can't trace at module level.
        """
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "--select=F401",
             "core/"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            assert False, (
                f"Ruff found unused imports in core/:\n{result.stdout}\n\n"
                "Fix these before committing.\n"
                "F401 — unused import (leftover from refactor)"
            )


"""Catch aliased imports whose aliases are never actually called —
a strong signal that call sites weren't updated after refactor.

Example: `from models import list_files as _lf` but every usage says `_lf(...)` → OK.
But if the alias is defined and NEVER used (ruff F401), it means someone renamed/moved a
function, added an alias for clarity, then forgot to update call sites to use that alias.
"""

class TestCoreModuleStructure:
    """Catch aliased imports whose aliases are never called in the file."""

    def test_no_unused_aliases_in_core_modules(self):
        """Each core module's lazy import aliases must actually be used somewhere."""
        errors = []
        import os as _os

        for fname in sorted(_os.listdir("core")):
            if not fname.endswith(".py") or fname.startswith("__"):
                continue
            with open(f"core/{fname}") as fh:
                content = fh.read()

            # Find all 'X as _alias' imports (both indented lazy and module-level)
            for m in re.finditer(r'(\w+)\s+as\s+(\_\w+)', content):
                orig, alias = m.group(1), m.group(2)

                # Skip names that have explicit re-export wrappers at module level
                skip_names = {'request', 'jsonify', 'abort', 'render_template'}
                if orig in skip_names or alias in skip_names:
                    continue
                
                # Skip _get_master_key — it's used both aliased (gmk) and unaliased (_get_master_key)
                # depending on which function body we're in, so this is intentional.
                if 'master_key' in orig.lower():
                    continue

                # Count calls to alias vs original name
                call_alias = len(re.findall(rf'(?<![.\w]){re.escape(alias)}\(', content))
                call_orig = len(re.findall(rf'(?<![.\w]){re.escape(orig)}\(', content))

                if call_alias == 0 and call_orig > 0:
                    errors.append(f"{fname}:{m.start(1)}: {orig} imported as {alias}, but called as {orig}() [{call_orig}x]")

        if errors:
            raise AssertionError(
                f"Alias-vs-call mismatches found:\n" + "\n".join(f"  - {e}" for e in sorted(set(errors))))


class TestCoreModuleCoverage:
    """Defense chain: verify core/ directory has actual modules (not empty after refactor).
    
    This catches the case where all files are moved out of helpers/ but into core/
    and tests still point to old paths, leaving a gap in coverage.
    """

    def test_core_directory_has_modules(self):
        """core/ directory must contain Python modules."""
        import os as _os
        
        core_dir = "core"
        py_files = [f for f in _os.listdir(core_dir) if f.endswith(".py") and not f.startswith("__")]
        assert len(py_files) > 0, (
            f"No Python modules found in {core_dir}/ — "
            f"expected at least one module but got none. Files: {py_files}"
        )
