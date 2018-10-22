import archinfo
import pyvex
import nose.tools


def test_s390x_exrl():
    arch = archinfo.ArchS390X()
    irsb = pyvex.lift(
        b'\xc6\x10\x00\x00\x00\x04'  # exrl %r1,0x400408
        b'\x07\xfe'  # br %r14
        b'\xd7\x00\x20\x00\x30\x00'  # xc 0(0,%r2),0(%r3)
        b'\x7d\xa7',  # padding
        0x400400,
        arch)
    nose.tools.assert_equal(str(irsb), '''IRSB {
   t0:Ity_I64 t1:Ity_I64 t2:Ity_I64 t3:Ity_I32 t4:Ity_I1 t5:Ity_I64 t6:Ity_I8 t7:Ity_I8 t8:Ity_I8 t9:Ity_I32 t10:Ity_I64 t11:Ity_I32 t12:Ity_I32 t13:Ity_I64 t14:Ity_I64 t15:Ity_I64 t16:Ity_I64 t17:Ity_I32 t18:Ity_I8 t19:Ity_I8 t20:Ity_I64 t21:Ity_I64 t22:Ity_I8 t23:Ity_I64 t24:Ity_I64 t25:Ity_I8 t26:Ity_I1 t27:Ity_I32 t28:Ity_I32 t29:Ity_I32 t30:Ity_I32 t31:Ity_I1 t32:Ity_I64 t33:Ity_I64 t34:Ity_I64

   00 | ------ IMark(0x400400, 6, 0) ------
   01 | t5 = LDbe:I64(0x0000000000400408)
   02 | t4 = CmpNE64(t5,0xd700200030007da7)
   03 | t4294967295 = DIRTY t4 TODO(effects) ::: s390x_dirtyhelper_EX(t5)
   04 | PUT(cmstart) = 0x0000000000400400
   05 | PUT(cmlen) = 0x0000000000000004
   06 | if (t4) { PUT(ia) = 0x400400; Ijk_InvalICache }
   07 | t14 = GET:I64(r2)
   08 | t16 = GET:I64(r3)
   09 | t19 = GET:I8(207)
   10 | t17 = 8Uto32(t19)
   11 | t9 = GET:I32(320)
   12 | t21 = 32Uto64(t9)
   13 | t20 = Add64(t14,t21)
   14 | t6 = LDbe:I8(t20)
   15 | t24 = 32Uto64(t9)
   16 | t23 = Add64(t16,t24)
   17 | t22 = LDbe:I8(t23)
   18 | t8 = Xor8(t6,t22)
   19 | t26 = CmpEQ64(t14,t16)
   20 | t25 = ITE(t26,0x00,t8)
   21 | STbe(t20) = t25
   22 | t28 = 8Uto32(t8)
   23 | t29 = GET:I32(324)
   24 | t27 = Or32(t28,t29)
   25 | PUT(324) = t27
   26 | t30 = Add32(t9,0x00000001)
   27 | PUT(320) = t30
   28 | t31 = CmpNE32(t9,t17)
   29 | if (t31) { PUT(ia) = 0x400400; Ijk_Boring }
   30 | PUT(352) = 0x0000000000000000
   31 | t32 = 32Uto64(t27)
   32 | PUT(360) = t32
   33 | PUT(368) = 0x0000000000000000
   34 | PUT(376) = 0x0000000000000000
   35 | PUT(320) = 0x0000000000000000
   36 | ------ IMark(0x400406, 2, 0) ------
   37 | t33 = GET:I64(r14)
   NEXT: PUT(ia) = t33; Ijk_Ret
}''')


if __name__ == '__main__':
    test_s390x_exrl()
