import copy
import re

import pyvex

# The 16-bit r/m table -- Intel SDM Vol. 2A, Table 2-1. It is not the table the 32-bit
# addressing modes use: r/m 4 is (%si) here and (%esp)+SIB there. mod 0 r/m 6 is a bare
# 16-bit literal address rather than (%bp), so it has no entry.
RM16 = {
    0: ("ebx", "esi"),
    1: ("ebx", "edi"),
    2: ("ebp", "esi"),
    3: ("ebp", "edi"),
    4: ("esi", None),
    5: ("edi", None),
    6: ("ebp", None),
    7: ("ebx", None),
}

_GET16 = re.compile(r"GET:I16\(offset=(\d+)\)")


def _lift(data):
    # The trailing ret keeps the amode's displacement and immediate inside the buffer.
    return pyvex.IRSB(data + b"\xc3", 0x400000, pyvex.ARCH_X86, opt_level=0, num_inst=1)


def _regs_read(irsb):
    """The names of the 16-bit guest registers the block reads."""
    text = " ".join(str(stmt) for stmt in irsb.statements)
    return {pyvex.ARCH_X86.translate_register_name(int(off), 2) for off in _GET16.findall(text)}


def _text(irsb):
    return " ".join(str(stmt) for stmt in irsb.statements)


def test_addr16_modrm_reads_the_right_registers():
    """
    A 0x67 prefix in 32-bit mode selects 16-bit addressing, which uses its own r/m table.
    disAMode16 indexed the general-register file with the raw r/m value instead, so
    `67 8b 47 10` -- mov 0x10(%bx),%eax -- decoded without complaint and read %di. The four
    base+index forms had no implementation at all and came back Ijk_NoDecode.
    """
    for mod, disp, size in ((0, b"", 3), (1, b"\x10", 4), (2, b"\x34\x12", 5)):
        for rm in range(8):
            if mod == 0 and rm == 6:
                continue  # a bare 16-bit literal address; see below
            irsb = _lift(bytes([0x67, 0x8B, (mod << 6) | rm]) + disp)
            base, index = RM16[rm]
            assert irsb.jumpkind == "Ijk_Boring", (mod, rm)
            assert irsb.size == size, (mod, rm)
            assert _regs_read(irsb) == ({base} if index is None else {base, index}), (mod, rm)


def test_addr16_bare_literal_address():
    # mod 0 r/m 6 is a 16-bit absolute address, not (%bp). This is the one form that was
    # already right, and it is here so the rest of the table has a control.
    irsb = _lift(b"\x67\x8b\x06\x34\x12")  # mov 0x1234,%eax
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 5
    assert _regs_read(irsb) == set()


def test_addr16_negative_disp8():
    # getSDisp8 sign-extends to 32 bits and the result went straight into mkU16, whose
    # `vassert(i < 65536)` failed, so every negative 8-bit displacement refused to decode.
    irsb = _lift(b"\x67\x8b\x47\xf0")  # mov -0x10(%bx),%eax
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 4
    assert _regs_read(irsb) == {"ebx"}
    assert "0xfff0" in _text(irsb)


def test_addr16_segment_override():
    # The effective address wraps within 64K and is then widened to 32 bits, and only after
    # that does the segment base get added. It used to reach handleSegOverride as an Ity_I16,
    # which builds a call taking a 32-bit address, and the block did not decode.
    irsb = _lift(b"\x67\x64\x8b\x47\x10")  # mov %fs:0x10(%bx),%eax
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 5
    assert _regs_read(irsb) == {"ebx", "fs"}
    assert "x86g_use_seg_selector" in _text(irsb)


def test_addr16_immediate_follows_the_16_bit_amode():
    """
    lengthAMode dispatched on the processor mode while disAMode dispatched on the address
    size in effect for the instruction, so a 0x67-prefixed amode was decoded 16-bit and
    measured 32-bit. Everything that locates its immediate with lengthAMode -- the Grp1/2/3/5/8
    extensions, SHLD/SHRD and the FPU escapes -- then read the immediate from the wrong byte.
    """
    # addl $5, 0x1234. The immediate used to be taken from 0x34, the low byte of the
    # displacement, because a bare 16-bit literal address was measured as one byte.
    irsb = _lift(b"\x67\x83\x06\x34\x12\x05")
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 6
    assert "0x00000005" in _text(irsb)
    assert "0x00000034" not in _text(irsb)

    # addl $5, (%di). The immediate used to be read three bytes past the end of the
    # instruction, because (%di) was measured as the 32-bit disp32 form.
    irsb = _lift(b"\x67\x83\x05\x05")
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 4
    assert _regs_read(irsb) == {"edi"}
    assert "0x00000005" in _text(irsb)


def _real_mode_arch():
    """A copy of ARCH_X86 with cr0.PE clear. ARCH_X86 is a module-level singleton, so it
    must not be mutated in place."""
    arch = copy.deepcopy(pyvex.ARCH_X86)
    arch.vex_archinfo["x86_cr0"] = 0xFFFFFFFE
    return arch


def test_addr16_in_real_mode_needs_no_prefix():
    """
    libVEX takes the address size from cr0 as well as from the prefix: with cr0.PE clear
    every memory ModRM goes through the 16-bit path with no 0x67 in front of it. angr
    lifts a BIOS in that mode, and it is where lengthAMode16's own lengths bite -- they
    put the immediate of an instruction that has one at the wrong byte.
    """
    arch = _real_mode_arch()

    # cmp dx, (%di). Same ModRM as the 0x67-prefixed case above, one byte shorter. Real
    # mode makes the operand size 16 bits as well, so %dx is read as an I16 here too.
    irsb = pyvex.IRSB(b"\x3b\x15" + b"\x90" * 4, 0xF9C98, arch, opt_level=0, num_inst=1)
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 2
    assert _regs_read(irsb) == {"edi", "edx"}

    # cmpw $0, 0xdf20. lengthAMode16 measured the bare 16-bit literal address as two
    # bytes rather than three, so the immediate came from the high half of the address.
    irsb = pyvex.IRSB(b"\x83\x3e\x20\xdf\x00" + b"\x90" * 4, 0xFE05D, arch, opt_level=0, num_inst=1)
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 5
    assert "0xdf20" in _text(irsb)
    assert "0xffdf" not in _text(irsb)

    # add ax, (%bx,%si). The base+index forms have no implementation at all on the base,
    # prefix or no prefix.
    irsb = pyvex.IRSB(b"\x03\x00" + b"\x90" * 4, 0xF9C11, arch, opt_level=0, num_inst=1)
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 2
    assert _regs_read(irsb) == {"ebx", "esi", "eax"}


def test_addr32_is_unchanged():
    # Control: without the prefix the same ModRM byte is 32-bit addressing off %edi, and
    # nothing in this change may touch it.
    irsb = _lift(b"\x8b\x47\x10")  # mov 0x10(%edi),%eax
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.size == 3
    assert _regs_read(irsb) == set()
    assert "GET:I32(offset=36)" in _text(irsb)


if __name__ == "__main__":
    test_addr16_modrm_reads_the_right_registers()
    test_addr16_bare_literal_address()
    test_addr16_negative_disp8()
    test_addr16_segment_override()
    test_addr16_immediate_follows_the_16_bit_amode()
    test_addr16_in_real_mode_needs_no_prefix()
    test_addr32_is_unchanged()
