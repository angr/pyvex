from . import Postprocessor, register, LiftingException
from . import libvex
from functools import reduce


class FixesPostProcessor(Postprocessor):

    def postprocess(self):
        if self.irsb.statements is None:
            # This is an optimized IRSB. We cannot really post-process it.
            return

        funcname = "_post_process_%s" % self.irsb.arch.name
        if hasattr(self, funcname):
            getattr(self, funcname)()

    def _post_process_MIPS32(self):
        # Handle unconditional branches
        # `beq $zero, $zero, xxxx`
        # It is translated to
        #
        # 15 | ------ IMark(0x401684, 4, 0) ------
        # 16 | t0 = CmpEQ32(0x00000000, 0x00000000)
        # 17 | PUT(128) = 0x00401688
        # 18 | ------ IMark(0x401688, 4, 0) ------
        # 19 | if (t0) goto {Ijk_Boring} 0x401684
        # 20 | PUT(128) = 0x0040168c
        # 21 | t4 = GET:I32(128)
        # NEXT: PUT(128) = t4; Ijk_Boring
        #

        stts = self.irsb.statements
        tmp_exit = None
        exit_stt_idx = None
        dst = None

        for i, stt in reversed(list(enumerate(stts))):
            if tmp_exit is None:
                # Looking for the Exit statement
                if isinstance(stt, stmt.Exit) and \
                        isinstance(stt.guard, expr.RdTmp):
                    tmp_exit = stt.guard.tmp
                    dst = stt.dst
                    exit_stt_idx = i
            else:
                # Looking for the WrTmp statement
                if isinstance(stt, stmt.WrTmp) and \
                                stt.tmp == tmp_exit:
                    if isinstance(stt.data, expr.Binop) and \
                                    stt.data.op == 'Iop_CmpEQ32' and \
                            isinstance(stt.data.child_expressions[0], expr.Const) and \
                            isinstance(stt.data.child_expressions[1], expr.Const) and \
                                    stt.data.child_expressions[0].con.value == stt.data.child_expressions[
                                1].con.value:

                        # Update statements
                        self.irsb.statements = self.irsb.statements[: exit_stt_idx] + self.irsb.statements[
                                                                                      exit_stt_idx + 1:]
                        # Create a new IRConst
                        irconst = expr.Const.get_instance(dst)
                        # Replace the default exit!
                        self.irsb.next = irconst

                    else:
                        break


for arch_name in libvex.SUPPORTED:
    register(FixesPostProcessor, arch_name)


from .. import stmt, expr
