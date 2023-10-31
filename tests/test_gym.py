# pylint: disable=missing-class-docstring
import unittest

import pyvex


class Tests(unittest.TestCase):
    def test_x86_aam(self):
        irsb = pyvex.lift(b"\xd4\x0b", 0, pyvex.ARCH_X86)
        self.assertEqual(irsb.jumpkind, "Ijk_Boring")
        self.assertEqual(irsb.size, 2)

    def test_x86_aad(self):
        irsb = pyvex.lift(b"\xd5\x0b", 0, pyvex.ARCH_X86)
        self.assertEqual(irsb.jumpkind, "Ijk_Boring")
        self.assertEqual(irsb.size, 2)

    def test_x86_xgetbv(self):
        irsb = pyvex.lift(b"\x0f\x01\xd0", 0, pyvex.ARCH_X86)
        self.assertEqual(irsb.jumpkind, "Ijk_Boring")
        self.assertEqual(irsb.size, 3)

    def test_x86_rdmsr(self):
        irsb = pyvex.lift(b"\x0f\x32", 0, pyvex.ARCH_X86)
        self.assertEqual(irsb.jumpkind, "Ijk_Boring")
        self.assertEqual(irsb.size, 2)


if __name__ == "__main__":
    unittest.main()
