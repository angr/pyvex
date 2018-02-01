from . import Postprocessor, register
from . import libvex

class ZeroDivisionPostProcessor(Postprocessor):
    """
    A postprocessor for adding zero-division checks to VEX.

    For "div rcx", will turn:

              00 | ------ IMark(0x8000, 3, 0) ------
              01 | t0 = GET:I64(rcx)
              02 | t1 = GET:I64(rax)
              03 | t2 = GET:I64(rdx)
              04 | t3 = 64HLto128(t2,t1)
              05 | t4 = DivModU128to64(t3,t0)
              06 | t5 = 128to64(t4)
              07 | PUT(rax) = t5
              08 | t6 = 128HIto64(t4)
              09 | PUT(rdx) = t6
              NEXT: PUT(rip) = 0x0000000000008003; Ijk_Boring

    into:

              00 | ------ IMark(0x8000, 3, 0) ------
              01 | t0 = GET:I64(rcx)
              02 | t1 = GET:I64(rax)
              03 | t2 = GET:I64(rdx)
              04 | t3 = 64HLto128(t2,t1)
              05 | if (CmpEQ(t12,0)) { PUT(pc) = 0x8000; Ijk_SigFPE_IntDiv }
              05 | t4 = DivModU128to64(t3,t0)
              06 | t5 = 128to64(t4)
              07 | PUT(rax) = t5
              08 | t6 = 128HIto64(t4)
              09 | PUT(rdx) = t6
              NEXT: PUT(rip) = 0x0000000000008003; Ijk_Boring

    """

    def postprocess(self):
        insertions = [ ]
        last_ip = 0
        for i,s in enumerate(self.irsb.statements):
            if s.tag == 'Ist_IMark':
                last_ip = s.addr
            if s.tag == 'Ist_WrTmp' and s.data.tag == 'Iex_Binop' and ('Div' in s.data.op or 'Mod' in s.data.op):
                cmp_args = [
                    s.data.args[1],
                    expr.Const(const.vex_int_class(s.data.args[1].result_size(self.irsb.tyenv))(0))
                ]
                insertions.append((i, stmt.Exit(
                    expr.Binop('Iop_CmpEQ', cmp_args),
                    const.vex_int_class(self.irsb.arch.bits)(last_ip),
                    'Ijk_SigFPE_IntDiv', self.irsb.offsIP
                )))

        for i,s in reversed(insertions):
            self.irsb.statements.insert(i,s)

for arch_name in libvex.SUPPORTED:
    register(ZeroDivisionPostProcessor, arch_name)

from .. import stmt, expr, const
