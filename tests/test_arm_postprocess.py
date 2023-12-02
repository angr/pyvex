import pyvex


##########################
### ARM Postprocessing ###
##########################
def test_arm_postprocess_call():
    for i in range(3):
        # Thumb

        # push  {r7}
        # add   r7, sp, #0
        # mov.w r1, #6
        # mov   r0, pc
        # add.w lr, r0, r1
        # b.w   10408
        irsb = pyvex.IRSB(
            data=(b"\x80\xb4" b"\x00\xaf" b"\x4f\xf0\x06\x01" b"\x78\x46" b"\x00\xeb\x01\x0e" b"\xff\xf7\xec\xbf"),
            mem_addr=0x1041F,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=6,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # mov   lr, pc
        # b.w   10408
        irsb = pyvex.IRSB(
            data=(b"\xfe\x46" b"\xe9\xe7"),
            mem_addr=0x10431,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=2,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # add   r2, pc, #0
        # add.w lr, r2, #4
        # ldr.w pc, [pc, #52]
        irsb = pyvex.IRSB(
            data=(b"\x00\xa2" b"\x02\xf1\x06\x0e" b"\xdf\xf8\x34\xf0"),
            mem_addr=0x10435,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # ldr   r0, [pc, #48]
        # mov   r1, pc
        # add.w r2, r1, #4
        # add.w r3, r2, #4
        # add.w r4, r3, #4
        # add.w lr, r4, #4
        # mov   pc, r0
        irsb = pyvex.IRSB(
            data=(
                b"\x0c\x48"
                b"\x79\x46"
                b"\x01\xf1\x04\x02"
                b"\x02\xf1\x04\x03"
                b"\x03\xf1\x04\x04"
                b"\x04\xf1\x04\x0e"
                b"\x87\x46"
            ),
            mem_addr=0x1043F,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=7,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # eor.w r0, r0, r0
        # mov   lr, pc
        # b.n   10460
        irsb = pyvex.IRSB(
            data=(b"\x80\xea\x00\x00" b"\x86\x46" b"\x01\xe0"),
            mem_addr=0x10455,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Boring"

        # Thumb compiled with optimizations (gcc -O2)

        # mov.w r1, #6
        # mov   r0, pc
        # add.w lr, r0, r1
        # b.w   104bc
        irsb = pyvex.IRSB(
            data=(b"\x4f\xf0\x06\x01" b"\x78\x46" b"\x00\xeb\x01\x0e" b"\x00\xf0\xc5\xb8"),
            mem_addr=0x10325,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=4,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # ldr   r0, [pc, #56]
        # mov   r1, pc
        # add.w r2, r1, #4
        # add.w r3, r2, #4
        # add.w r4, r3, #4
        # add.w lr, r4, #4
        # mov   pc, r0
        irsb = pyvex.IRSB(
            data=(
                b"\x0e\x48"
                b"\x79\x46"
                b"\x01\xf1\x04\x02"
                b"\x02\xf1\x04\x03"
                b"\x03\xf1\x04\x04"
                b"\x04\xf1\x04\x0e"
                b"\x87\x46"
            ),
            mem_addr=0x10333,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=7,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # add   r2, pc, #0
        # add.w lr, r2, #6
        # ldr.w pc, [pc, #28]
        irsb = pyvex.IRSB(
            data=(b"\x00\xa2" b"\x02\xf1\x06\x0e" b"\xdf\xf8\x1c\xf0"),
            mem_addr=0x10349,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # mov   lr, pc
        # b.w   104bc
        irsb = pyvex.IRSB(
            data=(b"\xfe\x46" b"\xb2\xe0"),
            mem_addr=0x10353,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=2,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # eor.w r0, r0, r0
        # mov   lr, pc
        # b.n   10362
        irsb = pyvex.IRSB(
            data=(b"\x80\xea\x00\x00" b"\x86\x46" b"\x01\xe0"),
            mem_addr=0x10357,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            bytes_offset=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Boring"

        # ARM compiled with optimizations (gcc -O2)

        # mov   r1, #4
        # mov   r0, pc
        # add   lr, r0, r1
        # ldr   pc, [pc, #56]
        irsb = pyvex.IRSB(
            data=(b"\x04\x10\xa0\xe3" b"\x0f\x00\xa0\xe1" b"\x01\xe0\x80\xe0" b"\x38\xf0\x9f\xe5"),
            mem_addr=0x10298,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=4,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # add   r1, pc, #0
        # add   r2, r1, #4
        # add   r3, r2, #4
        # add   r4, r3, #4
        # add   lr, r4, #4
        # b     10414
        irsb = pyvex.IRSB(
            data=(
                b"\x00\x10\x8f\xe2"
                b"\x04\x20\x81\xe2"
                b"\x04\x30\x82\xe2"
                b"\x04\x40\x83\xe2"
                b"\x04\xe0\x84\xe2"
                b"\x54\x00\x00\xea"
            ),
            mem_addr=0x102A8,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=6,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # mov   lr, pc
        # b     10414
        irsb = pyvex.IRSB(
            data=(b"\x0f\xe0\xa0\xe1" b"\x52\x00\x00\xea"),
            mem_addr=0x102C0,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=2,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # eor   r0, r0, r0
        # mov   lr, r0
        # b     102d8
        irsb = pyvex.IRSB(
            data=(b"\x00\x00\x20\xe0" b"\x00\xe0\xa0\xe1" b"\x00\x00\x00\xea"),
            mem_addr=0x102C8,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Boring"

        # ARM

        # push  {fp}
        # add   fp, sp, #0
        # mov   r1, #4
        # mov   r0, pc
        # add   lr, r0, r1
        # ldr   pc, [pc, #68]
        irsb = pyvex.IRSB(
            data=(
                b"\x04\xb0\x2d\xe5"
                b"\x00\xb0\x8d\xe2"
                b"\x04\x10\xa0\xe3"
                b"\x0f\x00\xa0\xe1"
                b"\x01\xe0\x80\xe0"
                b"\x44\xf0\x9f\xe5"
            ),
            mem_addr=0x103E8,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=6,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # add   r1, pc, #0
        # add   r2, r1, #4
        # add   r3, r2, #4
        # add   r4, r3, #4
        # add   lr, r4, #4
        # b     103c4
        irsb = pyvex.IRSB(
            data=(
                b"\x00\x10\x8f\xe2"
                b"\x04\x20\x81\xe2"
                b"\x04\x30\x82\xe2"
                b"\x04\x40\x83\xe2"
                b"\x04\xe0\x84\xe2"
                b"\x54\xff\xff\xea"
            ),
            mem_addr=0x10400,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=6,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # mov   lr, pc
        # b     103c4
        irsb = pyvex.IRSB(
            data=(b"\x0f\xe0\xa0\xe1" b"\xe8\xff\xff\xea"),
            mem_addr=0x10418,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=2,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"

        # eor   r0, r0, r0
        # mov   lr, r0
        # b     10430
        irsb = pyvex.IRSB(
            data=(b"\x00\x00\x20\xe0" b"\x00\xe0\xa0\xe1" b"\x00\x00\x00\xea"),
            mem_addr=0x10420,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=3,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Boring"

        # From a "real thing" compiled with armc
        # ARM:
        #
        irsb = pyvex.IRSB(
            data=(
                b"H\x10\x9b\xe5"
                b"\x0b\x00\xa0\xe1"
                b"\x04 \x91\xe5"
                b"\x04\xe0\x8f\xe2"
                b"\x01\x10\x82\xe0"
                b"\x01\xf0\xa0\xe1"
            ),
            mem_addr=0x264B4C,
            arch=pyvex.ARCH_ARM_LE,
            num_inst=6,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Call"


def test_arm_postprocess_ret():
    for i in range(3):
        # e91ba8f0
        # ldmdb  R11, {R4,R11,SP,PC}
        irsb = pyvex.IRSB(
            data=b"\xe9\x1b\xa8\xf0",
            mem_addr=0xED4028,
            arch=pyvex.ARCH_ARM_BE_LE,
            num_inst=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Ret"

        # e91badf0
        # ldmdb  R11, {R4-R8,R10,R11,SP,PC}
        irsb = pyvex.IRSB(
            data=b"\xe9\x1b\xa8\xf0",
            mem_addr=0x4D4028,
            arch=pyvex.ARCH_ARM_BE_LE,
            num_inst=1,
            opt_level=i,
        )
        assert irsb.jumpkind == "Ijk_Ret"

        # 00a89de8
        # ldmfd SP, {R11,SP,PC}
        # Fixed by Fish in the VEX fork, commit 43c78f608490f9a5c71c7fca87c04759c1b93741
        irsb = pyvex.IRSB(
            data=b"\x00\xa8\x9d\xe8",
            mem_addr=0xC800B57C,
            arch=pyvex.ARCH_ARM_BE,
            num_inst=1,
            opt_level=1,
        )
        assert irsb.jumpkind == "Ijk_Ret"


if __name__ == "__main__":
    test_arm_postprocess_call()
    test_arm_postprocess_ret()
