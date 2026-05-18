"""Regression test for HashHW value-slot truncation on 32-bit hosts.

See pyvex_c/analysis.c::HashHW. Before the fix, the cached register
value flowed through a `HWord` (= `unsigned long`, 32-bit on
wasm32-emscripten and other ILP32 hosts), silently dropping the high
32 bits of any guest pointer. The PoC below uses an AMD64 guest LEA +
memory load to land a 64-bit pointer in the HashHW.

https://github.com/angr/pyvex/issues/539
"""

import unittest

import archinfo

import pyvex


class TestDataRefs64BitTarget(unittest.TestCase):
    def test_64bit_guest_pointer_survives_hashhw_roundtrip(self):
        # 5 AMD64 instructions, 25 bytes. The mov at +0xe loads from
        # rdi - 4 where rdi was set by the previous lea to 0x100006324,
        # so the load target should be 0x100006320.
        blob = bytes.fromhex(
            "488d3d39b0feff"  # lea rdi, [rip - 0x14fc7]
            "bd14000000"  # mov ebp, 0x14
            "488d542420"  # lea rdx, [rsp + 0x20]
            "8b4ffc"  # mov ecx, dword ptr [rdi - 4]
            "e873300100"  # call rel32
        )
        irsb = pyvex.lift(
            blob,
            0x10001B2E4,
            archinfo.ArchAMD64(),
            max_inst=5,
            collect_data_refs=True,
            opt_level=1,
            cross_insn_opt=False,
        )
        sized_refs = [r for r in (irsb.data_refs or []) if r.ins_addr == 0x10001B2F5 and r.data_size == 4]
        assert sized_refs, "expected one size=4 ref from `mov ecx, [rdi - 4]`"
        self.assertEqual(
            sized_refs[0].data_addr,
            0x100006320,
            f"data_addr=0x{sized_refs[0].data_addr:x}; "
            "high 32 bits dropped — see pyvex_c/analysis.c HashHW value width",
        )


if __name__ == "__main__":
    unittest.main()
