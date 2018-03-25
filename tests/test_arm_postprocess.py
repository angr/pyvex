from past.builtins import xrange
import pyvex
import archinfo
import nose

##########################
### ARM Postprocessing ###
##########################
def test_arm_postprocess():
    for i in xrange(3):
        # Thumb

        # push  {r7}
        # add   r7, sp, #0
        # mov.w r1, #6
        # mov   r0, pc
        # add.w lr, r0, r1
        # b.w   10408
        irsb = pyvex.IRSB(data=('\x80\xb4'
                                '\x00\xaf'
                                '\x4f\xf0\x06\x01'
                                '\x78\x46'
                                '\x00\xeb\x01\x0e'
                                '\xff\xf7\xec\xbf'),
                          mem_addr=0x1041f,
                          arch=archinfo.ArchARMEL(),
                          num_inst=6,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # mov   lr, pc
        # b.w   10408
        irsb = pyvex.IRSB(data=('\xfe\x46'
                                '\xe9\xe7'),
                          mem_addr=0x10431,
                          arch=archinfo.ArchARMEL(),
                          num_inst=2,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # add   r2, pc, #0
        # add.w lr, r2, #4
        # ldr.w pc, [pc, #52]
        irsb = pyvex.IRSB(data=('\x00\xa2'
                                '\x02\xf1\x06\x0e'
                                '\xdf\xf8\x34\xf0'),
                          mem_addr=0x10435,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # ldr   r0, [pc, #48]
        # mov   r1, pc
        # add.w r2, r1, #4
        # add.w r3, r2, #4
        # add.w r4, r3, #4
        # add.w lr, r4, #4
        # mov   pc, r0
        irsb = pyvex.IRSB(data=('\x0c\x48'
                                '\x79\x46'
                                '\x01\xf1\x04\x02'
                                '\x02\xf1\x04\x03'
                                '\x03\xf1\x04\x04'
                                '\x04\xf1\x04\x0e'
                                '\x87\x46'),
                          mem_addr=0x1043f,
                          arch=archinfo.ArchARMEL(),
                          num_inst=7,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # eor.w r0, r0, r0
        # mov   lr, pc
        # b.n   10460
        irsb = pyvex.IRSB(data=('\x80\xea\x00\x00'
                                '\x86\x46'
                                '\x01\xe0'),
                          mem_addr=0x10455,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Boring')

        # Thumb compiled with optimizations (gcc -O2)

        # mov.w r1, #6
        # mov   r0, pc
        # add.w lr, r0, r1
        # b.w   104bc
        irsb = pyvex.IRSB(data=('\x4f\xf0\x06\x01'
                                '\x78\x46'
                                '\x00\xeb\x01\x0e'
                                '\x00\xf0\xc5\xb8'),
                          mem_addr=0x10325,
                          arch=archinfo.ArchARMEL(),
                          num_inst=4,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # ldr   r0, [pc, #56]
        # mov   r1, pc
        # add.w r2, r1, #4
        # add.w r3, r2, #4
        # add.w r4, r3, #4
        # add.w lr, r4, #4
        # mov   pc, r0
        irsb = pyvex.IRSB(data=('\x0e\x48'
                                '\x79\x46'
                                '\x01\xf1\x04\x02'
                                '\x02\xf1\x04\x03'
                                '\x03\xf1\x04\x04'
                                '\x04\xf1\x04\x0e'
                                '\x87\x46'),
                          mem_addr=0x10333,
                          arch=archinfo.ArchARMEL(),
                          num_inst=7,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # add   r2, pc, #0
        # add.w lr, r2, #6
        # ldr.w pc, [pc, #28]
        irsb = pyvex.IRSB(data=('\x00\xa2'
                                '\x02\xf1\x06\x0e'
                                '\xdf\xf8\x1c\xf0'),
                          mem_addr=0x10349,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # mov   lr, pc
        # b.w   104bc
        irsb = pyvex.IRSB(data=('\xfe\x46'
                                '\xb2\xe0'),
                          mem_addr=0x10353,
                          arch=archinfo.ArchARMEL(),
                          num_inst=2,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # eor.w r0, r0, r0
        # mov   lr, pc
        # b.n   10362
        irsb = pyvex.IRSB(data=('\x80\xea\x00\x00'
                                '\x86\x46'
                                '\x01\xe0'),
                          mem_addr=0x10357,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          bytes_offset=1,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Boring')

        # ARM compiled with optimizations (gcc -O2)

        # mov   r1, #4
        # mov   r0, pc
        # add   lr, r0, r1
        # ldr   pc, [pc, #56]
        irsb = pyvex.IRSB(data=('\x04\x10\xa0\xe3'
                                '\x0f\x00\xa0\xe1'
                                '\x01\xe0\x80\xe0'
                                '\x38\xf0\x9f\xe5'),
                          mem_addr=0x10298,
                          arch=archinfo.ArchARMEL(),
                          num_inst=4,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # add   r1, pc, #0
        # add   r2, r1, #4
        # add   r3, r2, #4
        # add   r4, r3, #4
        # add   lr, r4, #4
        # b     10414
        irsb = pyvex.IRSB(data=('\x00\x10\x8f\xe2'
                                '\x04\x20\x81\xe2'
                                '\x04\x30\x82\xe2'
                                '\x04\x40\x83\xe2'
                                '\x04\xe0\x84\xe2'
                                '\x54\x00\x00\xea'),
                          mem_addr=0x102a8,
                          arch=archinfo.ArchARMEL(),
                          num_inst=6,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # mov   lr, pc
        # b     10414
        irsb = pyvex.IRSB(data=('\x0f\xe0\xa0\xe1'
                                '\x52\x00\x00\xea'),
                          mem_addr=0x102c0,
                          arch=archinfo.ArchARMEL(),
                          num_inst=2,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # eor   r0, r0, r0
        # mov   lr, r0
        # b     102d8
        irsb = pyvex.IRSB(data=('\x00\x00\x20\xe0'
                                '\x00\xe0\xa0\xe1'
                                '\x00\x00\x00\xea'),
                          mem_addr=0x102c8,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Boring')

        # ARM

        # push  {fp}
        # add   fp, sp, #0
        # mov   r1, #4
        # mov   r0, pc
        # add   lr, r0, r1
        # ldr   pc, [pc, #68]
        irsb = pyvex.IRSB(data=('\x04\xb0\x2d\xe5'
                                '\x00\xb0\x8d\xe2'
                                '\x04\x10\xa0\xe3'
                                '\x0f\x00\xa0\xe1'
                                '\x01\xe0\x80\xe0'
                                '\x44\xf0\x9f\xe5'),
                          mem_addr=0x103e8,
                          arch=archinfo.ArchARMEL(),
                          num_inst=6,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # add   r1, pc, #0
        # add   r2, r1, #4
        # add   r3, r2, #4
        # add   r4, r3, #4
        # add   lr, r4, #4
        # b     103c4
        irsb = pyvex.IRSB(data=('\x00\x10\x8f\xe2'
                                '\x04\x20\x81\xe2'
                                '\x04\x30\x82\xe2'
                                '\x04\x40\x83\xe2'
                                '\x04\xe0\x84\xe2'
                                '\x54\xff\xff\xea'),
                          mem_addr=0x10400,
                          arch=archinfo.ArchARMEL(),
                          num_inst=6,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # mov   lr, pc
        # b     103c4
        irsb = pyvex.IRSB(data=('\x0f\xe0\xa0\xe1'
                                '\xe8\xff\xff\xea'),
                          mem_addr=0x10418,
                          arch=archinfo.ArchARMEL(),
                          num_inst=2,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Call')

        # eor   r0, r0, r0
        # mov   lr, r0
        # b     10430
        irsb = pyvex.IRSB(data=('\x00\x00\x20\xe0'
                                '\x00\xe0\xa0\xe1'
                                '\x00\x00\x00\xea'),
                          mem_addr=0x10420,
                          arch=archinfo.ArchARMEL(),
                          num_inst=3,
                          opt_level=i)
        nose.tools.assert_equals(irsb.jumpkind, 'Ijk_Boring')
