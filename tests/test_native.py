import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


@pytest.mark.skipif(sys.platform == "emscripten", reason="Pyodide cannot start a fresh Python subprocess")
def test_import_ignores_legacy_external_pickle_cache(tmp_path):
    package_root = Path(__file__).parents[1]
    script = textwrap.dedent("""
        import getpass
        import hashlib
        import os
        import pickle
        import runpy
        import sys
        import tempfile
        from pathlib import Path

        package_root = Path(sys.argv[1])
        tempfile.tempdir = sys.argv[2]
        temp_dir = Path(tempfile.gettempdir())
        ffi_str = runpy.run_path(str(package_root / "pyvex" / "vex_ffi.py"))["ffi_str"]
        try:
            username = getpass.getuser()
        except OSError:
            username = str(os.getuid())

        marker = temp_dir / "legacy-pickle-loaded"
        digest = hashlib.md5(ffi_str.encode("utf-8"), usedforsecurity=False).hexdigest()
        cache_path = temp_dir / f"pyvex_ffi_parser_cache.{username}.{digest}"

        class Marker:
            def __reduce__(self):
                return os.mkdir, (marker,)

        cache_path.write_bytes(pickle.dumps(Marker()))
        original_cache = cache_path.read_bytes()
        sys.path.insert(0, str(package_root))

        try:
            import pyvex
        except Exception:
            if marker.exists():
                raise AssertionError("pyvex loaded the legacy external pickle cache") from None
            raise

        assert not marker.exists()
        assert cache_path.read_bytes() == original_cache
        assert pyvex.ffi.typeof("IRSB *").kind == "pointer"
        """)
    env = os.environ.copy()
    for variable in ("TMPDIR", "TMP", "TEMP"):
        env[variable] = str(tmp_path)

    subprocess.run(
        [sys.executable, "-c", script, str(package_root), str(tmp_path)],
        check=True,
        cwd=tmp_path,
        env=env,
        timeout=30,
    )
