import os
import shutil
import tempfile
import unittest

import cffi

import pyvex.native


def _parse_into_fresh_ffi():
    """Parse the FFI string into a new FFI object and return the type names it declares."""
    pyvex.native.ffi = cffi.FFI()
    pyvex.native._parse_ffi_str()
    return pyvex.native.ffi.list_types()


class TestFFIParserCache(unittest.TestCase):
    """The parser cache only saves startup time, so a process that cannot write it must
    still come away with the declarations it needs."""

    def setUp(self):
        saved_ffi = pyvex.native.ffi
        saved_tempdir = tempfile.tempdir
        self.addCleanup(setattr, pyvex.native, "ffi", saved_ffi)
        self.addCleanup(setattr, tempfile, "tempdir", saved_tempdir)
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tempdir)
        tempfile.tempdir = self.tempdir

    def test_parses_when_the_cache_cannot_be_written(self):
        types = _parse_into_fresh_ffi()
        self.assertIn("IRSB", types[0])

        (cache_name,) = os.listdir(self.tempdir)
        cache_location = os.path.join(self.tempdir, cache_name)

        # Turn the cache into a directory so that replacing it fails on every platform.
        # Windows fails the same replacement with a PermissionError whenever another
        # process holds the cache file open for reading.
        os.unlink(cache_location)
        os.mkdir(cache_location)

        self.assertEqual(_parse_into_fresh_ffi(), types)
        self.assertEqual(os.listdir(self.tempdir), [cache_name])


if __name__ == "__main__":
    unittest.main()
